import scapy.all as scapy
#from .ftp_proxy import FTPProxy
#from ftplib import FTP
import queue
import pydivert
from .tcp_session import TCPSession
from .ftp_proxy import FTPProxy
from dataclasses import dataclass

SERVER_IP = "10.0.0.6"
SERVER_PORT = 21

CRLF = "\r\n"
B_CRLF = b"\r\n"


@dataclass
class Session():
    session: TCPSession
    data_commands: queue.Queue
    ftp_server: FTPProxy
    data_session: TCPSession = None

def get_dir(ftp, data_sock, callback):
    command = b"LIST\r\n"

    responses = ftp.send_cmd(command)
    print(responses)
    data_conn, sockaddr = data_sock.accept()
    while 1:
        data = data_conn.recv(8192)
        if not data:
            break
        callback(data)
    response = ftp.get_response()
    print(response)

def put_file(file, ftp, data_conn, callback=None):
    command = b"STOR Alice.txt\r\n"
    responses = ftp.send_cmd(command)
    print("Sent request. Answer:", responses)
    while True:
        buf = f.read(8192)
        if not buf:
            break
        data_conn.send(buf)
    data_conn.close()
    responses = ftp.get_response()
    print("Finished sending. Answer:", responses)

def get_file(ftp, data_conn, callback):
    command = b"RETR welcome.txt\r\n"
    responses = ftp.send_cmd(command)
    print("Sent request. Answer:", responses)
    while True:
        data = data_conn.recv(8192)
        if not data:
            break
        callback(data)
    data_conn.close()
    responses = ftp.get_response()
    print("Finished receiving. Answer:", responses)

buffer = []

filepath = r"C:\Users\itay6\Desktop\Alice.txt"

ftp = FTPProxy()
ftp.connect()
banner = ftp.get_response()
print(banner)
ftp.login_anonymously()

data_sock, responses = ftp.make_data_port()  # open data connection with server, and return response
data_conn, sockaddr = data_sock.accept()
#print("Opened data socket. Answer:", responses)
get_file(ftp, data_conn, buffer.append)
#with open(filepath, "rb") as f:
#    put_file(f, ftp, data_conn)
#ftp.quit()
"""client_seq = 0
client_ack = 0
client_port = 0

server_seq = 0
server_ack = 0

c = 0

w = pydivert.WinDivert("tcp.DstPort == 50001 or tcp.SrcPort == 50000")  # inbound packets
#w = pydivert.WinDivert("ip.DstAddr == 10.0.0.6 or 10.0.0.20")
w.open()
while True:

    packet = w.recv()
    if packet.src_addr == "10.0.0.6":  # server sent
        if packet.tcp.syn:
            server_ack = packet.tcp.seq_num + 1
        server_seq = packet.tcp.seq_num
        server_ack = packet.tcp.ack_num
        packet.src_port = 50001
    elif packet.src_addr == "10.0.0.20":  # client sent
        packet.dst_port = 50000
        client_port = packet.src_port
        client_seq = packet.tcp.seq_num
        client_ack = packet.tcp.ack_num
    print(packet)
    w.send(packet)
w.close()"""
