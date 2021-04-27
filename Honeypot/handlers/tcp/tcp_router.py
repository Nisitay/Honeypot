import threading
import pydivert
import queue
import scapy.all as scapy
from abc import ABC, abstractmethod
from collections import namedtuple

from ..logger import Logger
from ..blacklist import Blacklist
from .syn_handler import SynHandler

ClientAddr = namedtuple("ClientAddr", ["ip", "port"])


class TCPRouter(ABC):
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

        self._w = pydivert.WinDivert(f"tcp.DstPort == {self.fake_port} and inbound")
        self._running = threading.Event()
        self._handlers = self.get_new_threads()

        self.requests_to_handle = queue.Queue()
        self.blacklist = Blacklist()
        self.syns = SynHandler()
        self.logger = Logger("TCP Router").get_logger()

    @property
    def running(self):
        return self._running.is_set()

    @running.setter
    def running(self, running_state: bool):
        if running_state:
            self._running.set()
        else:
            self._running.clear()

    def start(self):
        if not self.running:
            self.running = True
            self._w.open()
            for handler in self._handlers:
                handler.start()
            self.logger.info("The router has been started successfully")

    def stop(self):
        if self.running:
            self.running = False
            scapy.send(scapy.IP(dst="127.0.0.1") /
                       scapy.TCP(sport=40000, dport=self.fake_port), verbose=0)
            self._w.close()
            self.requests_to_handle.put(None)
            self.logger.info("The router has been stopped successfully")
            self._handlers = self.get_new_threads()

    def get_new_threads(self):
        """
        Returns new instances of threads to be able to restart the router
        """
        return [
            threading.Thread(target=self.requests_handler, daemon=True),
            threading.Thread(target=self.packets_handler, daemon=True)
        ]

    def packets_handler(self):
        """
        Sends syn/fin/ack/payload packets to their corresponding handlers,
        and detects DOS attacks
        """
        while self.running:
            packet = self._w.recv()

            if packet.src_addr == "127.0.0.1":
                break

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
    def handle_payload_packet(self, packet: pydivert.Packet):
        pass

    @abstractmethod
    def handle_syn_packet(self, packet: pydivert.Packet):
        pass

    @abstractmethod
    def handle_fin_packet(self, packet: pydivert.Packet):
        pass

    def fingerprint(self, packet: pydivert.Packet):
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

    def add_to_blacklist(self, ip_addr):
        self.blacklist.add_address(ip_addr)
        self.logger.info(f"{ip_addr} has been added to blacklist")

    def update_settings(self, asset_ip, asset_port,
                        honeypot_ip, honeypot_port, fake_asset_port):
        self.asset_ip = asset_ip
        self.asset_port = asset_port
        self.honeypot_ip = honeypot_ip
        self.honeypot_port = honeypot_port
        self.fake_port = fake_asset_port
