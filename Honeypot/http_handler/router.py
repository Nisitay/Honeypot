import scapy.all as scapy
import pydivert
import logging
import random
import urllib
import socket
import re
from threading import Thread

from http_handler import db_updater
from http_handler.blacklist import Blacklist
from http_handler.syn_manager import SynManager
from http_handler.http_request import HTTPRequest
from http_handler.database import database

# TODO: Move to config file
BLACKLIST_PATH = "blacklist.txt"
LOG_PATH = "app.log"
MAX_SYNS_ALLOWED = 10
MAX_SEQUENCE_NUM = 4294967295


class HTTPRouter():
    def __init__(self, asset_ip, asset_port,
                 honeypot_ip, honeypot_port, fake_asset_port):

        self.asset_ip = asset_ip
        self.asset_port = asset_port
        self.honeypot_ip = honeypot_ip
        self.honeypot_port = honeypot_port
        self.fake_port = fake_asset_port

        self.w = pydivert.WinDivert(f"tcp.DstPort == {self.fake_port} and inbound")
        self.blacklist = Blacklist(BLACKLIST_PATH)
        self.syns = SynManager(MAX_SYNS_ALLOWED)
        self.requests_to_handle = []
        self.logged_into_hp = []
        self.handlers = [
            Thread(target=self.requests_handler, args=()),
            Thread(target=self.handle_packets, args=())
        ]
        self.initialize_logger()

    def start(self):
        self.w.open()
        for handler in self.handlers:
            handler.start()

    def stop(self):
        self.w.close()
        self.logger.info("HTTP router has stopped")

    def handle_packets(self):
        """
        Handles the syn/fin/ack packets, sends packets with a payload
        to the corresponding function, and detects DOS attacks
        """
        self.logger.info("HTTP router has started. Handling packets...")
        while True:
            packet = self.w.recv()

            if len(packet.payload) > 0 and packet.tcp.ack:
                ack = scapy.IP(src=self.asset_ip, dst=packet.ipv4.src_addr)\
                    / scapy.TCP(sport=self.fake_port, dport=packet.tcp.src_port, flags="A",
                                seq=packet.tcp.ack_num,
                                ack=packet.tcp.seq_num + len(packet.payload))
                scapy.send(ack, verbose=0)
                self.requests_to_handle.append(packet)

            elif packet.tcp.syn:
                self.syns.register_syn(packet.ipv4.src_addr)
                syn_ack = scapy.IP(src=self.asset_ip, dst=packet.ipv4.src_addr)\
                        / scapy.TCP(sport=self.fake_port, dport=packet.tcp.src_port, flags="SA",
                                    seq=random.randint(0, MAX_SEQUENCE_NUM),
                                    ack=packet.tcp.seq_num + 1)
                scapy.send(syn_ack, verbose=0)

            elif packet.tcp.fin:
                fin_ack = scapy.IP(src=self.asset_ip, dst=packet.ipv4.src_addr)\
                        / scapy.TCP(sport=self.fake_port, dport=packet.tcp.src_port, flags="FA",
                                    seq=packet.tcp.ack_num,
                                    ack=packet.tcp.seq_num)
                scapy.send(fin_ack, verbose=0)
                ack = scapy.IP(src=self.asset_ip, dst=packet.ipv4.src_addr)\
                    / scapy.TCP(sport=self.fake_port, dport=packet.tcp.src_port, flags="A",
                                seq=packet.tcp.ack_num + 1,
                                ack=packet.tcp.seq_num + 1)
                scapy.send(ack, verbose=0)

            else:  # ACK
                self.syns.register_ack(packet.ipv4.src_addr)

            if self.syns.is_syn_flooding(packet.ipv4.src_addr):
                self.logger.warning(f"DOS attack (SYN flood) detected from {packet.ipv4.src_addr}:{packet.tcp.src_port}")

    def requests_handler(self):
        """
        Handles incoming HTTP requests, and sends them to
        the honeypot/asset according to the contents of the request
        """
        while True:
            if self.requests_to_handle:
                packet = self.requests_to_handle.pop(0)
                request = HTTPRequest(packet.payload)  # Parse the HTTP request headers
                content_length = (int(request.headers.get("Content-Length", 0))
                                  if hasattr(request, "headers") else 0)

                full_payload = packet.payload
                content_match = self.get_http_content(full_payload)
                while not content_match or len(content_match.group("content")) < content_length:
                    while True:
                        if self.requests_to_handle: break
                    content_packet = self.requests_to_handle.pop(0)
                    full_payload += content_packet.payload
                    content_match = self.get_http_content(full_payload)

                login_match = self.get_login_creds(full_payload)
                if packet.ipv4.src_addr in self.logged_into_hp:
                    self.send_response(packet, full_payload, from_honeypot=True)

                elif not self.valid_payload(full_payload):
                    self.logger.warning(f"SQL Injection attack was caught from {packet.ipv4.src_addr}:{packet.tcp.src_port}")
                    probable_os = self.fingerprint(packet)

                    if packet.ipv4.src_addr not in self.blacklist:
                        self.blacklist.add_address(packet.ipv4.src_addr)
                        self.logger.info(f"{packet.ipv4.src_addr} has been added to blacklist")
                        self.logger.info(f"The OS of attacker at {packet.ipv4.src_addr} is probably: {probable_os}")

                    database.add_attacker(packet.ipv4.src_addr, probable_os)
                    database.add_attack(packet.ipv4.src_addr, packet.tcp.src_port, "Attempted SQL Injection attack")
                    self.logged_into_hp.append(packet.ipv4.src_addr)
                    self.send_response(packet, full_payload, from_honeypot=True)

                elif login_match:
                    email = urllib.parse.unquote(login_match.group("email").decode("utf-8"))
                    username = database.get_username(email)
                    if database.has_allowed(packet.ipv4.src_addr):
                        if database.is_allowed(packet.ipv4.src_addr, username) and packet.ipv4.src_addr not in self.blacklist:
                            self.send_response(packet, full_payload)
                        else:
                            probable_os = self.fingerprint(packet)
                            self.logger.warning(f"{packet.ipv4.src_addr} has logged in to a shadowed account.")
                            database.add_attacker(packet.ipv4.src_addr, probable_os)
                            database.add_attack(packet.ipv4.src_addr, packet.tcp.src_port,
                                                "Attempted to log into a prohibited account, or attacked before.")
                            self.logged_into_hp.append(packet.ipv4.src_addr)
                            self.send_response(packet, full_payload, from_honeypot=True)
                    else:
                        database.add_allowed(packet.ipv4.src_addr, username)
                        self.send_response(packet, full_payload)

                else:
                    response = self.send_response(packet, full_payload)
                    if b"302 FOUND" in response:
                        creds = self.get_register_creds(full_payload)
                        if None not in creds:
                            db_updater.add_new_user(creds[0], creds[1], "default.png", creds[2])

                if (hasattr(request, "path") and request.path == "/logout"
                   and packet.ipv4.src_addr in self.logged_into_hp):
                    self.logged_into_hp.remove(packet.ipv4.src_addr)

    def send_response(self, packet, payload, from_honeypot=False):
        """
        Gets a HTTP response from the server/honeypot, and sends it
        to the client.

        Args:
            packet (pydivert packet): First packet of the HTTP request
            payload (bytes): Full HTTP request
            from_honeypot (bool, optional): Determines if the response should
            be returned from the honeypot. Defaults to False.

        Returns:
            bytes: HTTP response in bytes
        """
        response = self.get_server_response(payload, from_honeypot)
        seq_num = packet.tcp.ack_num
        ack_num = packet.tcp.seq_num + len(payload)
        payloads = self.split_payload(response)

        for p in payloads:
            response_packet = scapy.IP(src=self.asset_ip, dst=packet.ipv4.src_addr)\
                            / scapy.TCP(sport=self.fake_port, dport=packet.tcp.src_port, flags="PA",
                                        seq=seq_num,
                                        ack=ack_num)\
                            / scapy.Raw(p)
            scapy.send(response_packet, verbose=0)
            seq_num += len(p)
        return response

    def get_server_response(self, http_request, honeypot):
        """
        Sends the HTTP request to the asset/honeypot,
        and returns the HTTP response.

        Args:
            http_request (bytes):
            honeypot (bool): Determines if the response
            should be returned from the honeypot.

        Returns:
            bytes: HTTP response in bytes
        """
        addr = (self.honeypot_ip, self.honeypot_port) if honeypot else (self.asset_ip, self.asset_port)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect(addr)
        server.send(http_request)
        http_response = b""

        while True:
            data = server.recv(2048)
            if not data: break
            http_response += data
        server.close()
        return http_response

    def valid_payload(self, payload):
        """
        Receives a HTTP payload as bytes,
        and checks it for SQL injection

        Args:
            payload (bytes): HTTP payload, as bytes

        Returns:
            bool: Returns whether the payload is valid or not
        """
        login_match = self.get_login_creds(payload)
        if not login_match: return True  # If no credentials, valid payload

        credentials = (login_match.group("email"),
                       login_match.group("password"))
        forbidden_chars = (urllib.parse.quote(b'"').encode("utf-8"),
                           urllib.parse.quote(b"'").encode("utf-8"))
        if any(char in cred for cred in credentials for char in forbidden_chars):
            return False
        return True

    def get_login_creds(self, payload):
        """
        Returns a regex match for login credentials in a
        HTTP request

        Args:
            payload (bytes): HTTP payload, as bytes

        Returns:
            re.Match: Returns the match or none if not found
        """
        pattern = b"email=(?P<email>.*)&password=(?P<password>.*)&submit=Log\+In"
        login_match = re.search(pattern, payload)
        return login_match

    def get_register_creds(self, payload):
        """
        Returns credentials used to register

        Args:
            payload (bytes): HTTP payload, as bytes

        Returns:
            list: [username, email, password] used for registering
        """
        pattern = b"username=(?P<username>.*)&email=(?P<email>.*)&password=(?P<password>.*)&confirm_password=.*&submit=Sign\+Up"
        register_match = re.search(pattern, payload)
        if not register_match: return [None, None, None]
        creds = [register_match.group("username"), register_match.group("email"), register_match.group("password")]
        return [urllib.parse.unquote(cred.decode("utf-8")) for cred in creds]

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

    def get_http_content(self, payload):
        """
        Returns a regex match for content in a
        HTTP request

        Args:
            payload (bytes): TCP payload - HTTP request

        Returns:
            re.Match: Returns the match or none if not found
        """
        pattern = b"\r\n\r\n(?P<content>(.|\s)*)"
        content_match = re.search(pattern, payload)
        return content_match

    def fingerprint(self, packet):
        """
        Calculates the most probable operating system of the packet source,
        based on the packets' closest original TTL and window size.

        Args:
            packet (pydivert packet):

        Returns:
            str: A string of the most probable OS
        """
        ttl = packet.ipv4.ttl
        window_size = packet.tcp.window_size
        closest_ttl = min(filter(lambda x: x >= ttl, [64, 128, 255]))
        os_mapper = {
            64: {
                5720: "Google's customized Linux",
                5840: "Linux (kernel 2.4 and 2.6)",
                16384: "OpenBSD, AIX 4.3",
                32120: "Linux (kernel 2.2)",
                65535: "FreeBSD"
            },
            128: {
                8192: "Windows 7, Vista, and Server 2008",
                16384: "Windows 2000",
                65535: "Windows XP"
            },
            255: {
                4128: "Cisco Router (IOS 12.4)",
                8760: "Solaris 7"
            }
        }

        probable_os = os_mapper.get(closest_ttl).get(window_size)
        if probable_os is None: probable_os = "Unknown OS"
        return probable_os

    def initialize_logger(self):
        """
        Initializes the logging in the app
        """
        open(LOG_PATH, "w").close()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        file_handler = logging.FileHandler(LOG_PATH)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)