from http_handler import HTTPRouter
from http_handler.config import (ASSET_IP, ASSET_PORT,
                                 HONEYPOT_IP, HONEYPOT_PORT, FAKE_ASSET_PORT)


def main():
    http_router = HTTPRouter(ASSET_IP, ASSET_PORT,
                             HONEYPOT_IP, HONEYPOT_PORT, FAKE_ASSET_PORT)
    http_router.start()
    while True:
        command = input("----> ")

        if "!help" in command:
            print("Examples:\n!unblock_ip 10.0.0.10\n!log\n!table attackers")
        elif "!unblock_ip" in command:
            ip_addr = command.split(" ")[1]
            http_router.remove_blocked_ip(ip_addr)
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
