import threading
import pydivert
import queue
from dataclasses import dataclass

from .. import database, Logger
from ..tcp import TCPRouter, TCPSession, ClientAddr
from .ftp_proxy import FTPProxy


@dataclass
class FTPSession:
    syn_packet: pydivert.Packet
    tcp_session: TCPSession
    ftp_server: FTPProxy
    data_commands: queue.Queue
    data_session: TCPSession = None


class FTPRouter(TCPRouter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sessions = {}
        self.server_sends_data = {b"NLST", b"LIST", b"RETR"}
        self.client_sends_data = {b"STOR"}
        self.data_channel_commands = self.server_sends_data.union(self.client_sends_data)
        self.whitelist_passwords = set()
        self.logger = Logger("FTP Router").get_logger()
        threading.Thread(target=self.catch_unwanted_resets, daemon=True).start()

    def handle_syn_packet(self, packet):
        session = TCPSession(self.asset_ip, self.fake_port, packet.src_addr, packet.src_port)
        session.register_syn(packet)

        ftp_proxy = FTPProxy((self.asset_ip, self.asset_port), (self.honeypot_ip, self.honeypot_port))
        ftp_proxy.connect()
        banner_messages = ftp_proxy.get_response()
        session.sendall(banner_messages)

        client_addr = ClientAddr(packet.src_addr, packet.src_port)
        self.sessions[client_addr] = FTPSession(packet, session, ftp_proxy, queue.Queue())

    def handle_payload_packet(self, packet):
        client_addr = ClientAddr(packet.src_addr, packet.src_port)
        self.sessions[client_addr].tcp_session.register_payload_packet(packet)
        self.requests_to_handle.put(packet)

    def handle_fin_packet(self, packet):
        client_addr = ClientAddr(packet.src_addr, packet.src_port)
        self.sessions[client_addr].tcp_session.disconnect()
        self.sessions[client_addr].ftp_server.close()
        del self.sessions[client_addr]

    def requests_handler(self):
        """
        registers incoming packets, and handles the HTTP
        requests once they are finished.
        """
        while self._running.is_set():
            packet = self.requests_to_handle.get()
            if not isinstance(packet, pydivert.Packet):  # Router Stopped
                break

            src_ip = packet.src_addr
            client_addr = ClientAddr(src_ip, packet.src_port)

            # command handling
            command, _, arg = packet.payload.rstrip(b"\r\n").partition(b" ")

            if command == b"PASS":
                responses = self.sessions[client_addr].ftp_server.send_cmd(packet.payload)
                if src_ip not in self.blacklist and arg in self.whitelist_passwords:
                    self.logger.info(f"Detected legit user from IP {src_ip}.")
                    if self.sessions[client_addr].ftp_server.connected_to_honeypot:
                        self.sessions[client_addr].ftp_server.convert_server(to_asset=True)
                else:  # attacker, convert him to the ftp honeypot
                    self.logger.info(f"Detected suspicious user from IP {src_ip}.")
                    self.add_to_blacklist(src_ip)
                    desc = "Used unpermitted password to use FTP server."
                    syn = self.sessions[client_addr].syn_packet
                    self.add_attack(src_ip, packet.src_port, syn, desc)
                    if self.sessions[client_addr].ftp_server.connected_to_asset:
                        self.sessions[client_addr].ftp_server.convert_server(to_honeypot=True)

            elif command == b"PORT":
                num1, num2 = [int(num) for num in arg.split(b",")[-2:]]
                port_num = (num1 * 256) + num2

                ftp = self.sessions[client_addr].ftp_server
                data_sock, responses = ftp.make_data_port()

                data_session = TCPSession(self.asset_ip, self.fake_port-1, src_ip, port_num)
                self.sessions[client_addr].data_session = data_session
                data_session.connect()
                threading.Thread(target=self.handle_data_channel, args=(client_addr, port_num, data_sock)).start()

            else:
                ftp_server = self.sessions[client_addr].ftp_server
                responses = ftp_server.send_cmd(packet.payload)
                if command in self.data_channel_commands:
                    self.sessions[client_addr].data_commands.put(command)
                if src_ip in self.blacklist:
                    self.logger.info(f"Attacker from IP address {src_ip} has tried to run a {command} command.")

            self.sessions[client_addr].tcp_session.sendall(responses)

    def handle_data_channel(self, client_addr, client_port, data_sock):
        data_conn, _ = data_sock.accept()
        data_session = self.sessions[client_addr].data_session

        command = self.sessions[client_addr].data_commands.get()
        if command in self.server_sends_data:
            while True:
                data = data_conn.recv(2048)
                if not data:
                    break
                data_session.send(data)
            data_conn.close()
            data_session.disconnect()
        else:
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
        responses = self.sessions[client_addr].ftp_server.get_response()
        self.sessions[client_addr].tcp_session.sendall(responses)

    def catch_unwanted_resets(self):
        w = pydivert.WinDivert(f"tcp.Rst and tcp.SrcPort == {self.fake_port-1}")
        w.open()
        while True:
            w.recv()

    def add_whitelist_password(self, password: str):
        self.whitelist_passwords.add(password.encode())

    def remove_whitelist_password(self, password: str):
        self.whitelist_passwords.remove(password.encode())
