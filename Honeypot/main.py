from handlers import HTTPRouter, FTPRouter

# temporary, should be user input
from handlers.config import (
    HTTP_ASSET_IP,
    ASSET_HTTP_PORT,
    FAKE_ASSET_HTTP_PORT,
    HTTP_HONEYPOT_IP,
    HONEYPOT_HTTP_PORT,
    FTP_ASSET_IP,
    ASSET_FTP_PORT,
    FAKE_ASSET_FTP_PORT,
    FTP_HONEYPOT_IP,
    HONEYPOT_FTP_PORT
)


def main():
    #http_router = HTTPRouter(HTTP_ASSET_IP, ASSET_HTTP_PORT,
    #                         HTTP_HONEYPOT_IP, HONEYPOT_HTTP_PORT, FAKE_ASSET_HTTP_PORT)
    ftp_router = FTPRouter(FTP_ASSET_IP, ASSET_FTP_PORT,
                           FTP_HONEYPOT_IP, HONEYPOT_FTP_PORT, FAKE_ASSET_FTP_PORT)
    ftp_router.start()
    #http_router.start()

    while True:
        command = input("----> ")
        if "!help" in command:
            print("Examples:\n!unblock_ip 10.0.0.10\n!log\n!table attackers")
        elif "!unblock_ip" in command:
            ip_addr = command.split(" ")[1]
            http_router.unblock_ip(ip_addr)
        elif "!log" in command:
            logs = http_router.get_log()
            print(logs)
        elif "!table" in command:
            table_name = command.split(" ")[1]
            print(http_router.get_table(table_name))
        else:
            print("Unknown command")


if __name__ == "__main__":
    main()
