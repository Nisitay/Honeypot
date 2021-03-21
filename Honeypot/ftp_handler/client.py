import time
from .ftp_proxy import FTPProxy
from ftplib import FTP
import pydivert
SERVER_IP = "10.0.0.16"
SERVER_PORT = 21

CRLF = "\r\n"
B_CRLF = b"\r\n"

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
    command = b"RETR Alice.txt\r\n"
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

ftp = FTPProxy("asset", SERVER_IP, SERVER_PORT)
ftp.connect()
banner = ftp.get_response()
ftp.login_anonymously()

data_sock, responses = ftp.make_data_port()  # open data connection with server, and return response
data_conn, sockaddr = data_sock.accept()
print("Opened data socket. Answer:", responses)
get_file(ftp, data_conn, buffer.append)
#with open(filepath, "rb") as f:
#    put_file(f, ftp, data_conn)
ftp.quit()

"""w = pydivert.WinDivert("tcp.SrcPort == 50000 or tcp.DstPort == 50000")
#w = pydivert.WinDivert("ip.DstAddr == 10.0.0.20 or ip.SrcAddr == 10.0.0.20")
w.open()
while True:
    packet = w.recv()
    if len(packet.payload) > 1:
        if packet.tcp.src_port == 50000:
            print("Detected first payload from server")
        else:
            print("Detected first payload from client")
        break
    w.send(packet)
    if len(packet.payload) > 1:
        #total_payload = packet.payload
        print(f"Total payload to expect: {packet.ipv4.packet_len - packet.ipv4.header_len - packet.tcp.header_len}")
        print(f"Received payload: {len(packet.payload)}")
        print(packet)
        print("------------------------------------------------------")
        while (packet.ipv4.packet_len != (packet.ipv4.header_len + packet.tcp.header_len + len(packet.payload))):
            print("Havent received all data, need to receive more")
            new_packet = w.recv()
            print(new_packet)
            packet.payload += new_packet.payload
            print(f"Received {len(new_packet.payload)} more")
        print(f"finished receiving all payload, total length {len(packet.payload)}")
        #packet.payload = total_payload
        #input("waiting for input and then sending packet...")
    w.send(packet)
w.close()"""
