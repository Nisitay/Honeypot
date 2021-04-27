from .singleton import Singleton
from .gui import GUI

BLACKLIST_PATH = r"Honeypot\common\blacklist.txt"


class Blacklist(metaclass=Singleton):
    """
    Stores the records of blacklisted IP addresses
    in a set and in a file, and keeps them in sync.
    """
    def __init__(self):
        self.file_path = BLACKLIST_PATH
        self.blacklist = set()
        self._initialize()

    def __contains__(self, ip_addr: str):
        return ip_addr in self.blacklist

    def aslist(self):
        return list(self.blacklist)

    def add_address(self, ip_addr: str):
        self.blacklist.add(ip_addr)
        GUI.add_to_blacklist(ip_addr)
        with open(self.file_path, "a") as f:
            f.write(ip_addr + "\n")

    def remove_address(self, ip_addr: str):
        self.blacklist.remove(ip_addr)
        with open(self.file_path, "w") as f:
            for ip in self.blacklist:
                f.write(ip + "\n")

    def _initialize(self):
        # Create file if doesn't exist/ Override if exists
        open(self.file_path, "w").close()
        with open(self.file_path, "r") as f:
            existing_ips = {line.rstrip("\n") for line in f}
        self.blacklist.update(existing_ips)