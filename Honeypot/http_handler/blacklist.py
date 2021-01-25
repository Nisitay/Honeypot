class Blacklist():
    """
    Stores the records of blacklisted IP addresses
    in a list and in a file, and keeps them in sync.
    """

    def __init__(self, file_path):
        self.file_path = file_path
        self.blacklist = []
        self.initialize_blacklist()

    def __contains__(self, ip_addr):
        return ip_addr in self.blacklist

    def initialize_blacklist(self):
        # Create file if doesn't exist/ Override if exists
        open(self.file_path, "w").close()
        with open(self.file_path, "r") as f:
            ips_list = [line.rstrip("\n") for line in f]
        self.blacklist.extend(ips_list)

    def add_address(self, ip_addr):
        self.blacklist.append(ip_addr)
        with open(self.file_path, "a") as f:
            f.write(ip_addr + "\n")

    def remove_address(self, ip_addr):
        self.blacklist.remove(ip_addr)
        with open(self.file_path, "r") as f:
            new_ips_list = [line.rstrip("\n") for line in f
                            if line.rstrip("\n") != ip_addr]
        with open(self.file_path, "w") as f:
            for ip in new_ips_list:
                f.write(ip + "\n")
