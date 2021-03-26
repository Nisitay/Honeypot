import threading
import pydivert
import queue
from dataclasses import dataclass

from ftp_handler.tcp_router import TCPRouter
from ftp_handler.tcp_session import TCPSession
from ftp_handler.ftp_proxy import FTPProxy


class FTPRouter(TCPRouter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.commands_to_handle = queue.Queue()
        self.sessions = {}
        self.server_sends_data = {b"NLST", b"LIST", b"RETR"}
        self.client_sends_data = {b"STOR"}
        self.data_channel_commands = self.server_sends_data.union(self.client_sends_data)
        self.whitelist_addresses = ["10.0.0.20"]
        self.whitelist_passwords = [b"itay123", b"itayking"]

    def handle_syn_packet(self, packet):
        session = TCPSession(self.asset_ip, self.fake_port, packet.src_addr, packet.src_port)
        session.register_syn(packet)

        ftp_proxy = FTPProxy()
        ftp_proxy.connect()
        banner_messages = ftp_proxy.get_response()
        session.sendall(banner_messages)
        self.sessions[packet.src_addr] = FTPSession(session, ftp_proxy, queue.Queue())

    def handle_payload_packet(self, packet):
        self.sessions[packet.src_addr].tcp_session.register_payload_packet(packet)
        self.commands_to_handle.put(packet)

    def handle_fin_packet(self, packet):
        self.sessions[packet.src_addr].tcp_session.register_fin(packet)
        self.sessions[packet.src_addr].ftp_server.close()

    def requests_handler(self):
        """
        registers incoming packets, and handles the HTTP
        requests once they are finished.
        """
        while self._running.isSet():
            packet = self.commands_to_handle.get()
            src_addr = packet.src_addr

            # command handling
            command, _, arg = packet.payload.rstrip(b"\r\n").partition(b" ")

            if command == b"PASS":
                responses = self.sessions[src_addr].ftp_server.send_cmd(packet.payload)
                if src_addr not in self.blacklist and \
                    (arg in self.whitelist_passwords or src_addr in self.whitelist_addresses):
                    if self.sessions[src_addr].ftp_server.connected_to_honeypot:
                        self.sessions[src_addr].ftp_server.convert_server(to_asset=True)
                else:  # attacker, convert him to the ftp honeypot
                    if self.sessions[src_addr].ftp_server.connected_to_asset:
                        self.sessions[src_addr].ftp_server.convert_server(to_honeypot=True)

            elif command == b"PORT":
                num1, num2 = [int(num) for num in arg.split(b",")[-2:]]
                port_num = (num1 * 256) + num2

                ftp = self.sessions[src_addr].ftp_server
                data_sock, responses = ftp.make_data_port()

                data_session = TCPSession(self.asset_ip, self.fake_port-1, src_addr, port_num)
                self.sessions[src_addr].data_session = data_session
                threading.Thread(target=self.catch_unwanted_resets).start()
                data_session.connect()  # connect to client
                threading.Thread(target=self.handle_data_channel, args=(src_addr, port_num, data_sock)).start()

            else:
                ftp_server = self.sessions[src_addr].ftp_server
                responses = ftp_server.send_cmd(packet.payload)
                if command in self.data_channel_commands:
                    self.sessions[src_addr].data_commands.put(command)

            self.sessions[src_addr].tcp_session.sendall(responses)

    def handle_data_channel(self, ip_addr, client_port, data_sock):
        data_conn, sockaddr = data_sock.accept()
        data_session = self.sessions[ip_addr].data_session
        command_queue = self.sessions[ip_addr].data_commands
        ftp = self.sessions[ip_addr].ftp_server

        command = command_queue.get()
        if command in self.server_sends_data:  # server sends data
            while True:
                data = data_conn.recv(2048)
                if not data:
                    break
                data_session.send(data)
            data_conn.close()
            data_session.disconnect()
        else:  # client sends data
            with pydivert.WinDivert(f"tcp.SrcPort == {client_port}") as w:
                for packet in w:
                    if (len(packet.payload) > 1 and packet.tcp.ack and
                            not (packet.tcp.seq_num < data_session.ack)):
                        data_session.register_payload_packet(packet)
                        data_conn.send(packet.payload)
                    elif packet.tcp.fin:
                        data_session.disconnect()
                        data_conn.close()
                        break
        responses = ftp.get_response()
        self.sessions[ip_addr].tcp_session.sendall(responses)
        del self.sessions[ip_addr].data_session

    def catch_unwanted_resets(self):
        w = pydivert.WinDivert(f"tcp.Rst and tcp.SrcPort == {self.fake_port-1}")
        w.open()
        while True:
            w.recv()


@dataclass
class FTPSession:
    tcp_session: TCPSession
    ftp_server: FTPProxy
    data_commands: queue.Queue
    data_session: TCPSession = None
