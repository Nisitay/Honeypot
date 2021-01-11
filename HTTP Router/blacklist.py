
DEFAULT_FILE_PATH = "blacklist.txt"


class Blacklist():
    def __init__(self, file_path=DEFAULT_FILE_PATH):
        self.file_path = file_path
        self.blacklist = []
        self.initialize_blacklist()

    def __contains__(self, ip_addr):
        return ip_addr in self.blacklist

    def initialize_blacklist(self):
        open(self.file_path, "w").close()  # Create file if doesn't exist
        with open(self.file_path, "r") as f:
            ips_list = [line.rstrip("\n") for line in f]
            self.blacklist.extend(ips_list)

    def add_address(self, ip_addr):
        self.blacklist.append(ip_addr)
        with open(self.file_path, "a") as f:
            f.write(ip_addr + "\n")
