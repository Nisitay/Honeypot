import threading
import pydivert
import logging
import abc

from abc import abstractmethod
from .blacklist import Blacklist
from .syn_handler import SynHandler


BLACKLIST_PATH = "blacklist.txt"
LOG_PATH = "app.log"
MAX_SYNS_ALLOWED = 10


class TCPRouter(abc.ABC):
    """
    Basic router structure to inherit from
    """
    def __init__(self, asset_ip, asset_port,
                 honeypot_ip, honeypot_port, fake_asset_port):

        self.asset_ip = asset_ip
        self.asset_port = asset_port
        self.honeypot_ip = honeypot_ip
        self.honeypot_port = honeypot_port
        self.fake_port = fake_asset_port
        self.logger = self.initialize_logger()

        self._w = pydivert.WinDivert(f"tcp.DstPort == {self.fake_port} and inbound")
        self._running = threading.Event()
        self._handlers = [
            threading.Thread(target=self.requests_handler, args=()),
            threading.Thread(target=self.packets_handler, args=())
        ]

        self.blacklist = Blacklist(BLACKLIST_PATH)
        self.syns = SynHandler(MAX_SYNS_ALLOWED)

    def start(self):
        self._running.set()
        self._w.open()
        for handler in self._handlers:
            handler.start()

    def packets_handler(self):
        """
        Sends syn/fin/ack/payload packets to their corresponding handlers,
        and detects DOS attacks
        """
        while self._running.isSet():
            packet = self._w.recv()

            if len(packet.payload) > 1 and packet.tcp.ack:
                self.handle_payload_packet(packet)

            elif packet.tcp.syn:
                self.handle_syn_packet(packet)
                self.syns.register_syn(packet.ipv4.src_addr)

            elif packet.tcp.fin:
                self.handle_fin_packet(packet)

            else:  # ACK
                self.syns.register_ack(packet.src_addr)

            if self.syns.is_syn_flooding(packet.src_addr):
                self.logger.warning(f"DOS attack (SYN flood) detected from {packet.src_addr}:{packet.src_port}")

    @abstractmethod
    def requests_handler(self):
        pass

    @abstractmethod
    def handle_payload_packet(self, packet):
        pass

    @abstractmethod
    def handle_syn_packet(self, packet):
        pass

    @abstractmethod
    def handle_fin_packet(self, packet):
        pass

    def fingerprint(self, packet):
        """
        Passive OS fingerprint - calculates the most probable operating system
        of the packet source, based on the packets' closest original TTL and
        window size.

        Args:
            packet (pydivert packet):

        Returns:
            str: A string of the most probable OS
        """
        ttl = packet.ipv4.ttl
        window_size = packet.tcp.window_size
        os_mapper = {
            64: {
                5720: "Google's customized Linux",
                5840: "Linux (kernel 2.4 and 2.6)",
                16384: "OpenBSD, AIX 4.3",
                32120: "Linux (kernel 2.2)",
                65535: "FreeBSD"
            },
            128: {
                8192: "Windows 7, Vista, and Server 2008",
                16384: "Windows 2000",
                65535: "Windows XP"
            },
            255: {
                4128: "Cisco Router (IOS 12.4)",
                8760: "Solaris 7"
            }
        }
        closest_ttl = min(filter(lambda x: x >= ttl, os_mapper.keys()))
        probable_os = os_mapper.get(closest_ttl).get(window_size)
        return probable_os if probable_os else "Unknown OS"

    def initialize_logger(self):
        """
        Initializes the router logger,
        and creates the log file if it doesn't exist/ overrides if it exists

        Returns:
            logging.Logger: router logger
        """
        open(LOG_PATH, "w").close()
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(name)s| %(asctime)s | %(levelname)s | %(message)s")
        file_handler = logging.FileHandler(LOG_PATH)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        return logger

    def unblock_ip(self, ip_addr):
        if ip_addr in self.blacklist:
            self.blacklist.remove_address(ip_addr)
            self.logger.info(f"IP address {ip_addr} was unblocked by the admin.")