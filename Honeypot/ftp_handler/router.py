import pydivert
import scapy.all as scapy
import threading
import random

import ftplib
from ftp_handler.ftp_proxy import FTPProxy
from ftp_handler.blacklist import Blacklist
from ftp_handler.ftp_session import TCPSession

MAX_SYNS_ALLOWED = 10
MAX_SEQUENCE_NUM = 4294967295
BLACKLIST_PATH = "blacklist.txt"


class FTPRouter():
    def __init__(self, asset_ip, asset_port,
                 honeypot_ip, honeypot_port, fake_asset_port):

        self.asset_ip = asset_ip
        self.asset_port = asset_port
        self.honeypot_ip = honeypot_ip
        self.honeypot_port = honeypot_port
        self.fake_port = fake_asset_port

        self._w = pydivert.WinDivert(f"tcp.DstPort == {self.fake_port} and inbound")
        self._running = threading.Event()
        self._handlers = [
            threading.Thread(target=self.requests_handler, args=()),
            threading.Thread(target=self.packets_handler, args=())
        ]

        self.commands_to_handle = []
        self.sessions = {}
        """
        src_addr:{
           'ftp_server': current handling ftp server
        }
        """
        self.server_sends_data = [b"NLST", b"LIST", b"RETR"]
        self.client_sends_data = [b"STOR"]
        #self.blacklist = Blacklist(BLACKLIST_PATH)
        self.whitelist_addresses = ["10.0.0.20"]
        self.whitelist_passwords = [b"itay123", b"itayking"]

    def start(self):
        self._running.set()
        self._w.open()
        for handler in self._handlers:
            handler.start()

    def stop(self):
        self._running.clear()
        self._w.close()

    def packets_handler(self):
        """
        Handles incoming packets to the command channel,
        sends packets with a payload to the corresponding function,
        and detects DOS attacks
        """
        while self._running.isSet():
            packet = self._w.recv()

            if len(packet.payload) > 1 and packet.tcp.ack:
                self.sessions[packet.src_addr]["session"].register_payload_packet(packet)
                self.commands_to_handle.append(packet)

            elif packet.tcp.syn:
                session = TCPSession(self.asset_ip, self.fake_port, packet.src_addr, packet.src_port)
                self.sessions[packet.src_addr] = {"session": session}
                session.register_syn(packet)

                ftp_proxy = FTPProxy("asset", self.asset_ip, self.asset_port)
                ftp_proxy.connect()
                banner_messages = ftp_proxy.get_response()
                self.sessions[packet.src_addr]["ftp_server"] = ftp_proxy
                session.send_all(banner_messages)

            elif packet.tcp.fin:
                self.sessions[packet.src_addr]["session"].register_fin(packet)
                self.sessions[packet.src_addr]["ftp_server"].quit()

            else:  # ACK
                pass

    def requests_handler(self):
        """
        registers incoming packets, and handles the HTTP
        requests once they are finished.
        """
        while self._running.isSet():
            if self.commands_to_handle:
                packet = self.commands_to_handle.pop(0)
                src_addr = packet.src_addr

                # command handling
                command = packet.payload.rstrip(b"\r\n")

                if b"PASS" in command:  # user entered password
                    responses = self.sessions[src_addr]["ftp_server"].send_cmd(packet.payload)
                    password = command.split()[1]
                    #if (src_addr not in self.blacklist and (password in self.whitelist_passwords or src_addr in self.whitelist_addresses)):  # authenticated
                    if password in self.whitelist_passwords or src_addr in self.whitelist_addresses:
                        if self.sessions[src_addr]["ftp_server"].connected_to_honeypot:
                            self.convert_to_asset(src_addr)
                        print("Detected legit user. Asset should be used for uploading files")
                    else: # attacker, convert him to the ftp honeypot
                        if self.sessions[src_addr]["ftp_server"].connected_to_asset:
                            self.convert_to_honeypot(src_addr)
                        print("Detected anonymous user. Honeypot should be used for uploading files")

                elif b"PORT" in command:  # client requests for port
                    addr = command.split()[1]
                    num1, num2 = [int(num) for num in addr.split(b",")[-2:]]
                    port_num = self.calculate_port(num1, num2)  # client wants server to connect to this port

                    ftp = self.sessions[src_addr]["ftp_server"]
                    data_sock, responses = ftp.make_data_port()  # open data connection with server, and return response

                    data_session = TCPSession(self.asset_ip, self.fake_port-1, src_addr, port_num)
                    self.sessions[src_addr]["data_session"] = data_session
                    data_session.connect()  # connect to client
                    threading.Thread(target=self.handle_data_channel, args=(src_addr, port_num, data_sock)).start()

                else:  # Regular command - just send command and return response
                    ftp_server = self.sessions[src_addr]["ftp_server"]
                    responses = ftp_server.send_cmd(packet.payload)

                session = self.sessions[src_addr]["session"]
                session.send_all(responses)

    def handle_data_channel(self, ip_addr, client_port, data_sock):
        # initiate data channel connection
        data_port = data_sock.getsockname()[1]  # port to talk with server
        data_conn, sockaddr = data_sock.accept()
        data_session = self.sessions[ip_addr]["data_session"]

        ftp = self.sessions[ip_addr]["ftp_server"]
        w2 = pydivert.WinDivert(f"tcp.SrcPort == {client_port} or tcp.DstPort == {data_port}")
        client_sending = False
        server_sending = False
        w2.open()
        packet = w2.recv()
        if packet.src_port == client_port:
            client_sending = True
            print("Client is sending data. Listening for data from client...")
        elif packet.dst_port == data_port:
            server_sending = True
            print("Server is sending data. Listening for data from server...")
        w2.close()
        if server_sending:
            while True:
                data = data_conn.recv(2048)
                data_session.send(data)
                if not data:
                    break
            data_conn.close()
            data_session.register_fin(None)

        elif client_sending:
            w3 = pydivert.WinDivert(f"tcp.SrcPort == {client_port}")
            w3.open()
            while True:
                packet = w3.recv()
                if len(packet.payload) > 1 and packet.tcp.ack:  # data packet
                    data_session.register_payload_packet(packet)
                    data_conn.send(packet.payload)
                elif packet.tcp.fin:
                    data_session.register_fin(packet)
                    data_conn.close()
                    break
            w3.close()
        responses = ftp.get_response()
        self.sessions[ip_addr]["session"].send_all(responses)
        """while True:
            packet = w2.recv()
            from_client = packet.tcp.src_port == client_port  # if the packet was sent from client
            from_server = packet.tcp.dst_port == data_port  # if the packet was sent from server

            if len(packet.payload) > 1 and packet.tcp.ack:  # data packet
                print(len(packet.payload))
                if from_client:
                    ftp.register_payload_packet(packet)
                    data_conn.send(packet.payload)
                elif from_server:
                    w2.send(packet)  # let data_conn handle with server
                    data_session.send(packet.payload)

            elif packet.tcp.fin:
                data_session.register_fin(packet)
                data_conn.close()
                responses = ftp.get_response()
                self.sessions[ip_addr]["session"].send_all(responses)
                break

            elif packet.tcp.ack:
                if from_server:
                    w2.send(packet)
        w2.close()"""

    def convert_to_asset(self, ip_addr):
        self.sessions[ip_addr]["ftp_server"].quit()  # close connection with honeypot
        ftp_asset = FTPProxy("asset")
        self.sessions[ip_addr]["ftp_server"] = ftp_asset  # set new instance for asset
        ftp_asset.connect_to_server(self.asset_ip, self.asset_port)
        ftp_asset.get_server_response()  # skip banner
        ftp_asset.login_anonymously()

    def convert_to_honeypot(self, ip_addr):
        self.sessions[ip_addr]["ftp_server"].quit()  # close connection with asset
        ftp_honeypot = FTPProxy("honeypot")
        self.sessions[ip_addr]["ftp_server"] = ftp_honeypot  # set new instance for honeypot
        ftp_honeypot.connect_to_server(self.honeypot_ip, self.honeypot_port)
        ftp_honeypot.get_server_response()  # skip banner
        ftp_honeypot.login_anonymously()

    def split_payload(self, payload):
        """
        Receives a payload, splits it to a list of payloads,
        each with maximum length that scapy can send.

        Args:
            payload (bytes): TCP payload

        Returns:
            list: List of payloads
        """
        max_payload_length = 1000  # MTU = 1500
        payloads = [payload[i:i+max_payload_length]
                    for i in range(0, len(payload), max_payload_length)]
        return payloads

    def calculate_port(self, num1, num2):
        """
        Receives 2 numbers from the FTP 'PORT' command
        and returns the calculated port

        Args:
            num1 (int):
            num2 (int):
        """
        return (num1 * 256) + num2
