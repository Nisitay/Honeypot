from xmlrpc.client import ServerProxy
from http_handler.config import HTTP_HONEYPOT_IP


def add_new_user(username, email, image_file_name, password):
    with ServerProxy(f"http://{HTTP_HONEYPOT_IP}:50000", allow_none=True) as s:
        s.add_new_user(username, email, image_file_name, password)