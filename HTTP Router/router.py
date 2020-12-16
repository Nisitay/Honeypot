import scapy.all as scapy
import pydivert
import random
import urllib
import socket
import re
from threading import Thread
from blacklist import Blacklist
from http_request import HTTPRequest
from utils import fingerprint


ASSET_IP = "10.0.0.10"
ASSET_PORT = 8080
FAKE_ASSET_PORT = 8000

HONEYPOT_IP = "10.0.0.18"
HONEYPOT_PORT = 8080

WINDIVERT_FILTER = f"tcp.DstPort == {FAKE_ASSET_PORT} and inbound"
MAX_SEQUENCE_NUM = 4294967295


class HTTPRouter():
    def __init__(self):
        self.w = pydivert.WinDivert(WINDIVERT_FILTER)
        self.blacklist = Blacklist()
        self.requests_to_handle = []
        self.syns = {}
        self.handlers = [
            Thread(target=self.requests_handler, args=()),
            Thread(target=self.handle_packets, args=())
        ]

    def start(self):
        self.w.open()
        for handler in self.handlers:
            handler.start()

    def stop(self):
        self.w.close()

    def handle_packets(self):
        print("Handling packets...")
        while True:
            packet = self.w.recv()

            if len(packet.payload) > 0 and packet.tcp.ack:
                ack = scapy.IP(src=ASSET_IP, dst=packet.ipv4.src_addr)\
                    / scapy.TCP(sport=FAKE_ASSET_PORT, dport=packet.tcp.src_port, flags="A",
                                seq=packet.tcp.ack_num,
                                ack=packet.tcp.seq_num + len(packet.payload))
                scapy.send(ack, verbose=0)
                self.requests_to_handle.append(packet)

            elif packet.tcp.syn:
                self.syns[packet.ipv4.src_addr] = self.syns.get(packet.ipv4.src_addr, 0) + 1
                syn_ack = scapy.IP(src=ASSET_IP, dst=packet.ipv4.src_addr)\
                        / scapy.TCP(sport=FAKE_ASSET_PORT, dport=packet.tcp.src_port, flags="SA",
                                    seq=random.randint(0, MAX_SEQUENCE_NUM),
                                    ack=packet.tcp.seq_num + 1)
                scapy.send(syn_ack, verbose=0)

            elif packet.tcp.fin:
                fin_ack = scapy.IP(src=ASSET_IP, dst=packet.ipv4.src_addr)\
                        / scapy.TCP(sport=FAKE_ASSET_PORT, dport=packet.tcp.src_port, flags="FA",
                                    seq=packet.tcp.ack_num,
                                    ack=packet.tcp.seq_num)
                scapy.send(fin_ack, verbose=0)
                ack = scapy.IP(src=ASSET_IP, dst=packet.ipv4.src_addr)\
                    / scapy.TCP(sport=FAKE_ASSET_PORT, dport=packet.tcp.src_port, flags="A",
                                seq=packet.tcp.ack_num + 1,
                                ack=packet.tcp.seq_num + 1)
                scapy.send(ack, verbose=0)

            else:  # ACK
                self.syns.pop(packet.ipv4.src_addr, None)

            if self.syns.get(packet.ipv4.src_addr, 0) >= 10:
                self.syns.pop(packet.ipv4.src_addr, None)
                print(f"DOS attack (SYN flood) detected from {packet.ipv4.src_addr}")

    def requests_handler(self):
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

                if self.valid_payload(full_payload):
                    self.send_response(packet, full_payload)
                else:
                    if packet.ipv4.src_addr not in self.blacklist:
                        self.blacklist.add_address(packet.ipv4.src_addr)
                    self.send_response(packet, full_payload, from_honeypot=True)

    def send_response(self, packet, payload, from_honeypot=False):
        """
        Gets a HTTP response from the server/honeypot, and sends it
        to the client.

        Args:
            packet (pydivert packet): First packet of the HTTP request
            payload (bytes): Full HTTP request
            from_honeypot (bool, optional): Determines if the response should
            be returned from the honeypot. Defaults to False.
        """
        response = self.get_server_response(payload, from_honeypot)
        seq_num = packet.tcp.ack_num
        ack_num = packet.tcp.seq_num + len(payload)
        payloads = self.split_payload(response)

        for p in payloads:
            response_packet = scapy.IP(src=ASSET_IP, dst=packet.ipv4.src_addr)\
                            / scapy.TCP(sport=FAKE_ASSET_PORT, dport=packet.tcp.src_port, flags="PA",
                                        seq=seq_num,
                                        ack=ack_num)\
                            / scapy.Raw(p)
            scapy.send(response_packet, verbose=0)
            seq_num += len(p)

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
        addr = (HONEYPOT_IP, HONEYPOT_PORT) if honeypot else (ASSET_IP, ASSET_PORT)
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
        pattern = b"email=(?P<email>.*)&password=(?P<password>.*)&submit=Log\+In"
        login_match = re.search(pattern, payload)
        if not login_match: return True  # If no credentials, valid payload

        credentials = (login_match.group("email"),
                       login_match.group("password"))
        forbidden_chars = (urllib.parse.quote(b'"').encode("utf-8"),
                           urllib.parse.quote(b"'").encode("utf-8"))
        if any(char in cred for cred in credentials for char in forbidden_chars):
            return False
        return True

    def split_payload(self, payload):
        """
        Receives a payload, splits it to a list of payloads,
        each with maximum length that scapy can send.

        Args:
            payload (bytes): TCP payload

        Returns:
            list: List of payloads
        """
        max_payload_length = 1000  # Max checked is 1460
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


if __name__ == "__main__":
    router = HTTPRouter()
    router.start()
