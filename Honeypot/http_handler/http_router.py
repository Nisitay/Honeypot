import urllib
import socket
import re

from http_handler.router import Router
from http_handler.tcp_session import TCPSession
from http_handler import db_updater
from http_handler.http_request import HTTPRequest
from http_handler.database import database


class HTTPRouter(Router):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.logged_into_hp = []
        self.requests_to_handle = []
        self.requests = {}
        self.sessions = {}

    def handle_syn_packet(self, packet):
        session = TCPSession(self.asset_ip, self.fake_port, packet.src_addr, packet.src_port)
        session.register_syn(packet)
        self.sessions[(packet.src_addr, packet.src_port)] = session

    def handle_payload_packet(self, packet):
        session = self.sessions[(packet.src_addr, packet.src_port)]
        if packet.tcp.seq_num < session.ack:  # Retransmission
            return
        session.register_payload_packet(packet)
        self.requests_to_handle.append(packet)

    def handle_fin_packet(self, packet):
        self.sessions[(packet.src_addr, packet.src_port)].register_fin(packet)

    def requests_handler(self):
        """
        registers incoming packets, and handles the HTTP
        requests once they are finished.
        """
        while self._running.isSet():
            if self.requests_to_handle:
                packet = self.requests_to_handle.pop(0)
                src_addr = packet.src_addr
                self.register_packet(packet)
                if self.finished_request(self.requests[src_addr]):
                    self.handle_http_request(self.requests[src_addr])
                    del self.requests[src_addr]

    def finished_request(self, request):
        """
        Checks whether the request is finished

        Args:
            request (dict)

        Returns:
            bool
        """
        content_match = self.get_http_content(request["request_bytes"])
        if not content_match or len(content_match.group("content")) < request["content_length"]:
            return False
        return True

    def handle_http_request(self, request):
        """
        Handles a finished http request

        Args:
            request (dict) : A request dict.
        """
        full_payload = request["request_bytes"]
        packet = request["first_packet"]
        src_addr = packet.src_addr
        src_port = packet.src_port
        request_headers = HTTPRequest(full_payload)

        login_match = self.get_login_creds(full_payload)
        if src_addr in self.logged_into_hp:
            self.send_response(src_addr, src_port, full_payload, from_honeypot=True)

        elif not self.valid_payload(full_payload):
            self.logger.warning(f"SQL Injection attack was caught from {src_addr}:{src_port}")
            probable_os = self.fingerprint(packet)

            if src_addr not in self.blacklist:
                self.blacklist.add_address(src_addr)
                self.logger.info(f"{src_addr} has been added to blacklist")
                self.logger.info(f"The OS of attacker at {src_addr} is probably: {probable_os}")

            database.add_attacker(src_addr, probable_os)
            database.add_attack(src_addr, src_port, "Attempted SQL Injection attack")
            self.logged_into_hp.append(src_addr)
            self.send_response(src_addr, src_port, full_payload, from_honeypot=True)

        elif login_match:
            email = urllib.parse.unquote(login_match.group("email").decode("utf-8"))
            username = database.get_username(email)
            if database.has_allowed(src_addr):
                if database.is_allowed(src_addr, username) and src_addr not in self.blacklist:
                    self.send_response(src_addr, src_port, full_payload)
                else:
                    if src_addr not in self.blacklist:
                        self.blacklist.add_address(src_addr)
                    probable_os = self.fingerprint(packet)
                    self.logger.warning(f"{src_addr} has logged in to a shadowed account.")
                    database.add_attacker(src_addr, probable_os)
                    database.add_attack(src_addr, src_port,
                                        "Attempted to log into a prohibited account")
                    self.logged_into_hp.append(src_addr)
                    self.send_response(src_addr, src_port, full_payload, from_honeypot=True)
            else:
                database.add_allowed(src_addr, username)
                self.send_response(src_addr, src_port, full_payload)

        else:
            response = self.send_response(src_addr, src_port, full_payload)
            if b"302 FOUND" in response:
                creds = self.get_register_creds(full_payload)
                if None not in creds:
                    db_updater.add_new_user(creds[0], creds[1], "default.png", creds[2])

        if (hasattr(request_headers, "path") and request_headers.path == "/logout"
           and src_addr in self.logged_into_hp):
            self.logged_into_hp.remove(src_addr)

    def register_packet(self, packet):
        """
        Registers a packet into the "requests" dict
        with the needed request inforamtion

        Args:
            packet (pydivert.packet)
        """
        src_addr = packet.src_addr
        payload = packet.payload
        if src_addr not in self.requests:
            request_headers = HTTPRequest(payload)
            content_length = (int(request_headers.headers.get("Content-Length", 0))
                              if hasattr(request_headers, "headers") else 0)
            self.requests[src_addr] = {
                "first_packet": packet,
                "content_length": content_length,
                "request_bytes": payload
            }
        else:
            self.requests[src_addr]["request_bytes"] += payload

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
        response = self.get_server_response(payload, from_honeypot)
        self.sessions[(src_addr, src_port)].send(response)
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
            if not data:
                break
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
        if not login_match:
            return True  # If no credentials, valid payload

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
        if not register_match:
            return [None, None, None]
        creds = [register_match.group("username"), register_match.group("email"), register_match.group("password")]
        return [urllib.parse.unquote(cred.decode("utf-8")) for cred in creds]

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

    def get_table(self, table_name):
        return database.get_pretty_table(table_name)

    def get_log(self):
        with open(LOG_PATH, "r") as f:
            logs = f.read()
        return logs
