import socket
from .utils import get_content_length, get_http_content

HTTP_HEADER_DELIMITER = b"\r\n\r\n"
CONTENT_LENGTH_FIELD = b"Content-Length:"


class HTTPProxy():
    def __init__(self, asset_addr, honeypot_addr):
        self.asset_addr = asset_addr
        self.honeypot_addr = honeypot_addr
        self.target = self.asset_addr

    @property
    def connected_to_asset(self):
        return self.target == self.asset_addr

    @property
    def connected_to_honeypot(self):
        return self.target == self.honeypot_addr

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(self.target)

    def convert_server(self, to_asset=False, to_honeypot=False):
        self.close()
        self.target = self.honeypot_addr if to_honeypot else self.asset_addr
        self.connect()

    def send_request(self, request):
        """
        Sends an HTTP request and returns the HTTP response.

        Args:
            request (bytes): HTTP request

        Returns:
            bytes: HTTP response
        """
        self._send(request)
        return self.get_response()

    def get_response(self):
        """
        Reads a full HTTP response

        Returns:
            bytes: HTTP response
        """
        response = self._read_until(self._end_of_header)
        content_match = get_http_content(response)
        content = content_match.group("content") if content_match else b""
        self.content_length = get_content_length(response)
        response += self._read_until(self._end_of_content, len(content))
        return response

    def close(self):
        sock = self.sock
        self.sock = None
        if sock:
            sock.close()

    def _read_until(self, condition, length_start=0, buffer=2048):
        """
        Reads HTTP data until the condition returns True

        Args:
            condition (func):
            length_start (int, optional): Receieved body length. Defaults to 0.
            buffer (int, optional): Socket buffer. Defaults to 2048.

        Returns:
            bytes: HTTP data
        """
        data = b""
        chunk = b""
        length = length_start
        while not condition(length, chunk):
            chunk = self.sock.recv(buffer)
            if not chunk:
                break
            data += chunk
            length += len(chunk)
        return data

    def _end_of_header(self, length, data):
        """
        Returns true if data contains the end-of-header marker.
        """
        return b"\r\n\r\n" in data

    def _end_of_content(self, length, data):
        """
        Returns true if length does not fullfil the content length.
        """
        return self.content_length <= length

    def _send(self, request):
        self.sock.send(request)
