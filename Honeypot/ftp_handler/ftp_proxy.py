import socket

CRLF = "\r\n"
B_CRLF = b"\r\n"

FTP_ASSET_IP = "10.0.0.6"
ASSET_FTP_PORT = 21

FTP_HONEYPOT_IP = "10.0.0.20"
HONEYPOT_FTP_PORT = 21

ASSET_ADDR = (FTP_ASSET_IP, ASSET_FTP_PORT)
HONEYPOT_ADDR = (FTP_HONEYPOT_IP, HONEYPOT_FTP_PORT)


class FTPProxy():
    """
    Handles connection with the FTP asset/honeypot - sends raw FTP commands
    using sockets and returns the answer.
    Connects to the asset at first, and able to convert to honeypot/server.
    """
    def __init__(self):
        self.target = ASSET_ADDR
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.maxline = 8192
        self.encoding = "utf-8"

    @property
    def connected_to_asset(self):
        return self.target == ASSET_ADDR

    @property
    def connected_to_honeypot(self):
        return self.target == HONEYPOT_ADDR

    def connect(self):
        self.sock.connect(self.target)
        self.file = self.sock.makefile("r")

    def convert_server(self, to_asset=False, to_honeypot=False):
        """
        Converts an FTP server (honeypot -> server / server -> honeypot)

        Args:
            to_asset (bool, optional): Defaults to False.
            to_honeypot (bool, optional): Defaults to False.
        """
        self.quit()
        self.target = HONEYPOT_ADDR if to_honeypot else ASSET_ADDR
        self.connect()
        self._get_multiline()  # skip banner
        self.login_anonymously()

    def login_anonymously(self):
        """
        Logins to the FTP server using anonymous credentials
        """
        username = b"anonymous"
        password = b"anonymous"
        self.send_cmd(b"USER " + username + B_CRLF)
        self.send_cmd(b"PASS " + password + B_CRLF)

    def get_response(self):
        """
        Reads the server response from the socket

        Returns:
            list: list of responses
        """
        return self._get_multiline()

    def send_cmd(self, cmd):
        """
        Send a command and return the response

        Args:
            cmd (bytes): FTP command

        Returns:
            list: list of responses
        """
        self._send_command(cmd)
        return self._get_multiline()

    def make_data_port(self):
        """
        Creates a new socket for data channel and sends a PORT command for it.

        Returns:
            tuple: data sock and the response to the PORT command
        """
        err = None
        sock = None
        for res in socket.getaddrinfo(None, 0, socket.AF_INET, socket.SOCK_STREAM, 0, socket.AI_PASSIVE):
            af, socktype, proto, canonname, sa = res
            try:
                sock = socket.socket(af, socktype, proto)
                sock.bind(sa)
            except OSError as _:
                err = _
                if sock:
                    sock.close()
                sock = None
                continue
            break
        if sock is None:
            if err is not None:
                raise err
            else:
                raise OSError("getaddrinfo returns an empty list")
        sock.listen(1)
        port = sock.getsockname()[1]
        host = self.sock.getsockname()[0]
        response = self._send_port_command(host, port)
        return sock, response

    def quit(self):
        self.send_cmd(b"QUIT\r\n")
        self.close()

    def close(self):
        try:
            file = self.file
            self.file = None
            if file is not None:
                file.close()
        finally:
            sock = self.sock
            self.sock = None
            if sock is not None:
                sock.close()

    def _get_line(self):
        """Reads a single line from the server over the command channel

        Returns:
            bytes: Response line
        """
        line = self.file.readline(self.maxline + 1)
        if len(line) > self.maxline:
            print(f"ERROR: got more than {self.maxline} bytes")
        if not line:
            print("Received EOF")
        if line[-2:] == CRLF:
            line = line[:-2]
        elif line[-1:] in CRLF:
            line = line[:-1]
        return line + CRLF

    def _get_multiline(self):
        """Reads multiple lines from the server over the command channel

        Returns:
            list: list of responses
        """
        lines = []
        line = self._get_line()
        lines.append(line)
        if line[3:4] == "-":
            code = line[:3]
            while 1:
                nextline = self._get_line()
                lines.append(nextline)
                if nextline[:3] == code and nextline[3:4] != "-":
                    break
        return lines

    def _send_port_command(self, host, port):
        """Sends a PORT command to the server to open a data channel.

        Args:
            host (str)
            port (int)

        Returns:
            bytes: The response
        """
        hbytes = host.split('.')
        pbytes = [repr(port//256), repr(port%256)]
        cmd = "PORT " + ",".join(hbytes + pbytes) + CRLF
        response = self.send_cmd(cmd.encode(self.encoding))
        return response

    def _send_command(self, cmd):
        self.sock.send(cmd)
