class SynHandler():
    """
    Keeps track of SYN packets from different IP addresses.
    """

    def __init__(self, max_syns_allowed):
        self.ips = {}
        self.max_syns_allowed = max_syns_allowed

    def register_syn(self, ip_addr):
        if ip_addr in self.ips:
            self.ips[ip_addr] += 1
        else:
            self.ips[ip_addr] = 1

    def register_ack(self, ip_addr):
        if ip_addr in self.ips:
            del self.ips[ip_addr]

    def is_syn_flooding(self, ip_addr):
        if ip_addr in self.ips and self.ips[ip_addr] > self.max_syns_allowed:
            del self.ips[ip_addr]
            return True
        return False
