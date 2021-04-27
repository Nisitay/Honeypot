from ..config import general_conf


class SynHandler:
    """
    Keeps track of SYN packets from different IP addresses.
    """
    max_syns_allowed = general_conf.max_syns_allowed

    def __init__(self):
        self.ips = {}

    def register_syn(self, ip_addr: str):
        if ip_addr in self.ips:
            self.ips[ip_addr] += 1
        else:
            self.ips[ip_addr] = 1

    def register_ack(self, ip_addr: str):
        if ip_addr in self.ips:
            del self.ips[ip_addr]

    def is_syn_flooding(self, ip_addr: str) -> bool:
        if ip_addr in self.ips and self.ips[ip_addr] > self.max_syns_allowed:
            del self.ips[ip_addr]
            return True
        return False
