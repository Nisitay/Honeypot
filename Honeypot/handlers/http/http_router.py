import pydivert
import urllib
from dataclasses import dataclass
from xmlrpc.client import ServerProxy

from .. import TCPRouter, TCPSession, ClientAddr
from ..logger import Logger
from .http_proxy import HTTPProxy
from ..database import database
from .http_request import HTTPRequest
from .utils import finished_request, get_login_creds, get_register_creds, get_content_length


@dataclass
class HTTPSession:
    tcp_session: TCPSession
    http_server: HTTPProxy
    content_length: int = 0
    request_bytes: bytes = b""


class HTTPRouter(TCPRouter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logged_into_hp = set()
        self.sessions = {}
        self.logger = Logger("HTTP Router").get_logger()

    def handle_syn_packet(self, packet):
        session = TCPSession(self.asset_ip, self.fake_port, packet.src_addr, packet.src_port)
        session.register_syn(packet)
        client_addr = ClientAddr(packet.src_addr, packet.src_port)
        http_server = HTTPProxy((self.asset_ip, self.asset_port), (self.honeypot_ip, self.honeypot_port))
        http_server.connect()
        self.sessions[client_addr] = HTTPSession(session, http_server)

    def handle_payload_packet(self, packet):
        client_addr = ClientAddr(packet.src_addr, packet.src_port)
        session = self.sessions[client_addr].tcp_session
        if packet.tcp.seq_num < session.ack:  # TCP retransmission
            return
        session.register_payload_packet(packet)
        self.requests_to_handle.put(packet)

    def handle_fin_packet(self, packet):
        client_addr = ClientAddr(packet.src_addr, packet.src_port)
        self.sessions[client_addr].tcp_session.disconnect()
        self.sessions[client_addr].http_server.close()
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

            client_addr = ClientAddr(packet.src_addr, packet.src_port)
            session = self.sessions[client_addr]
            self.register_packet(packet)
            if finished_request(session.request_bytes, session.content_length):
                self.handle_http_request(session.request_bytes, packet)
                session.content_length = 0
                session.request_bytes = b""

    def handle_http_request(self, request_bytes, packet):
        """
        Handles a finished HTTP request

        Args:
            request_bytes (bytes) : Full HTTP request.
            packet (pydivert.Packet)
        """
        full_payload = request_bytes
        src_addr = packet.src_addr
        src_port = packet.src_port
        request_headers = HTTPRequest(full_payload)
        login_match = get_login_creds(full_payload)

        if src_addr in self.logged_into_hp:
            self.send_response(src_addr, src_port, full_payload, from_honeypot=True)

        elif not self.valid_payload(full_payload):
            self.logger.warning(f"SQL Injection attack was caught from {src_addr}:{src_port}")
            probable_os = self.fingerprint(packet)

            if src_addr not in self.blacklist:
                self.add_to_blacklist(src_addr)
                self.logger.info(f"The OS of attacker at {src_addr} is probably: {probable_os}")

            database.add_attacker(src_addr, probable_os)
            database.add_attack(src_addr, src_port, "Attempted SQL Injection attack")
            self.logged_into_hp.add(src_addr)
            self.send_response(src_addr, src_port, full_payload, from_honeypot=True)

        elif login_match:
            email = urllib.parse.unquote(login_match.group("email").decode())
            username = database.get_username(email)
            if database.has_allowed(src_addr):
                if database.is_allowed(src_addr, username) and src_addr not in self.blacklist:
                    self.send_response(src_addr, src_port, full_payload)
                else:
                    if src_addr not in self.blacklist:
                        self.add_to_blacklist(src_addr)
                    probable_os = self.fingerprint(packet)
                    self.logger.warning(f"{src_addr} has logged in to a shadowed account.")
                    database.add_attacker(src_addr, probable_os)
                    database.add_attack(src_addr, src_port,
                                        "Attempted to log into a prohibited account")
                    self.logged_into_hp.add(src_addr)
                    self.send_response(src_addr, src_port, full_payload, from_honeypot=True)
            else:
                database.add_allowed(src_addr, username)
                self.send_response(src_addr, src_port, full_payload)

        else:
            response = self.send_response(src_addr, src_port, full_payload)
            if b"302 FOUND" in response:
                creds = get_register_creds(full_payload)
                if None not in creds:
                    self.add_new_user(creds[0], creds[1], "default.png", creds[2])

        if (hasattr(request_headers, "path") and request_headers.path == "/logout"
           and src_addr in self.logged_into_hp):
            self.logged_into_hp.remove(src_addr)

    def register_packet(self, packet):
        """
        Registers a packet to the correct session
        with the needed request inforamtion

        Args:
            packet (pydivert.packet)
        """
        payload = packet.payload
        client_addr = ClientAddr(packet.src_addr, packet.src_port)
        session = self.sessions[client_addr]
        if not session.request_bytes:
            session.content_length = get_content_length(payload)
        session.request_bytes += payload

    def send_response(self, src_addr, src_port, payload, from_honeypot=False):
        """
        Gets a HTTP response from the server/honeypot, and sends it
        to the client.

        Args:
            src_addr (str): Client IP address
            payload (bytes): Full HTTP request
            from_honeypot (bool, optional): Determines if the response should
            be returned from the honeypot. Defaults to False.

        Returns:
            bytes: HTTP response in bytes
        """
        client_addr = ClientAddr(src_addr, src_port)
        http_server = self.sessions[client_addr].http_server

        if from_honeypot and http_server.connected_to_asset:
            http_server.convert_server(to_honeypot=True)
        elif not from_honeypot and http_server.connected_to_honeypot:
            http_server.convert_server(to_asset=True)
        response = http_server.send_request(payload)
        self.sessions[client_addr].tcp_session.send(response)
        return response

    def valid_payload(self, payload: bytes) -> bool:
        """
        Receives a HTTP payload as bytes,
        and checks it for SQL injection

        Args:
            payload (bytes): HTTP payload, as bytes

        Returns:
            bool: Returns whether the payload is valid or not
        """
        login_match = get_login_creds(payload)
        if not login_match:
            return True

        credentials = login_match.groups()
        forbidden_chars = (urllib.parse.quote('"').encode(),
                           urllib.parse.quote("'").encode())
        if any(char in cred for cred in credentials for char in forbidden_chars):
            return False
        return True

    def add_new_user(self, username, email, image_filename, password):
        url = f"http://{self.honeypot_ip}:50000"
        with ServerProxy(url, allow_none=True) as s:
            s.add_new_user(username, email, image_filename, password)
