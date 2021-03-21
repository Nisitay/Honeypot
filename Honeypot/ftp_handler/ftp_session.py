import scapy.all as scapy
import random

MAX_SEQUENCE_NUM = 4294967295


class TCPSession():
    """
    Listens in the router and handles a TCP session between
    the client and the router
    """
    def __init__(self, router_ip, router_port, client_ip, client_port):
        self.router_ip = router_ip
        self.client_ip = client_ip
        self.router_port = router_port
        self.client_port = client_port
        self.seq = 0
        self.ack = 0

    def connect(self):
        """
        Connects to the client - sends syn packet, waits for syn ack,
        then returns ack to finish handshake)
        """
        self.seq = random.randint(0, MAX_SEQUENCE_NUM)
        syn = scapy.IP(src=self.router_ip, dst=self.client_ip)\
            / scapy.TCP(sport=self.router_port, dport=self.client_port, flags="S",
                        seq=self.seq,
                        ack=self.ack)
        self.seq += 1
        syn_ack = scapy.sr1(syn, verbose=0)

        self.ack = syn_ack[scapy.TCP].seq + 1
        ack = scapy.IP(src=self.router_ip, dst=self.client_ip)\
            / scapy.TCP(sport=self.router_port, dport=self.client_port, flags="A",
                        seq=self.seq,
                        ack=self.ack)
        scapy.send(ack, verbose=0)

    def register_syn_ack(self, syn_ack_packet):
        """
        Receives a syn-ack packet and finishes the handshake
        (returns an ack packet)

        Args:
            syn_ack_packet (pydivert.Packet): a pydivert packet
        """
        self.ack = syn_ack_packet.tcp.seq_num + 1
        ack = scapy.IP(src=self.router_ip, dst=self.client_ip)\
            / scapy.TCP(sport=self.router_port, dport=self.client_port, flags="A",
                        seq=self.seq,
                        ack=self.ack)
        scapy.send(ack, verbose=0)

    def register_syn(self, syn_packet):
        """
        Receives a syn packet and accepts the connection
        (returns a syn-ack packet)

        Args:
            syn_packet (pydivert.Packet): a pydivert packet
        """
        self.ack = syn_packet.tcp.seq_num + 1
        self.seq = random.randint(0, MAX_SEQUENCE_NUM)
        syn_ack = scapy.IP(src=self.router_ip, dst=self.client_ip)\
            / scapy.TCP(sport=self.router_port, dport=self.client_port, flags="SA",
                        seq=self.seq,
                        ack=self.ack)
        scapy.send(syn_ack, verbose=0)
        self.seq += 1

    def disconnect(self):
        fin_ack = scapy.IP(src=self.router_ip, dst=self.client_ip)\
            / scapy.TCP(sport=self.router_port, dport=self.client_port, flags="FA",
                        seq=self.seq,
                        ack=self.ack)
        scapy.send(fin_ack, verbose=0)
        self.seq += 1
        self.ack += 1
        ack = scapy.IP(src=self.router_ip, dst=self.client_ip)\
            / scapy.TCP(sport=self.router_port, dport=self.client_port, flags="A",
                        seq=self.seq,
                        ack=self.ack)
        scapy.send(ack, verbose=0)

    def register_fin(self, fin_packet):
        """
        Receives a fin packet and closes the connection
        (returns a fin-ack packet)

        Args:
            fin_packet (pydivert.Packet): a pydivert packet
        """
        fin_ack = scapy.IP(src=self.router_ip, dst=self.client_ip)\
            / scapy.TCP(sport=self.router_port, dport=self.client_port, flags="FA",
                        seq=self.seq,
                        ack=self.ack)
        scapy.send(fin_ack, verbose=0)
        self.seq += 1
        self.ack += 1
        ack = scapy.IP(src=self.router_ip, dst=self.client_ip)\
            / scapy.TCP(sport=self.router_port, dport=self.client_port, flags="A",
                        seq=self.seq,
                        ack=self.ack)
        scapy.send(ack, verbose=0)

    def register_payload_packet(self, payload_packet):
        """
        Receives a packet with payload and returns ack packet

        Args:
            payload_packet (pydivert.Packet): a pydivert packet
        """
        self.ack += len(payload_packet.payload)
        ack = scapy.IP(src=self.router_ip, dst=self.client_ip)\
            / scapy.TCP(sport=self.router_port, dport=self.client_port, flags="A",
                        seq=self.seq,
                        ack=self.ack)
        scapy.send(ack, verbose=0)

    def send_all(self, payloads):
        """
        Receives a list of payloads to send, and sends them

        Args:
            payloads (list): list of bytes/strings
        """
        for payload in payloads:
            self.send(payload)

    def send(self, payload):
        """
        Receives a payload and sends it to the client,
        and splits payloads bigger than MTU to multiple packets

        Args:
            payload (str/bytes): a TCP payload
        """
        for payload in self._split_payload(payload):
            p = scapy.IP(src=self.router_ip, dst=self.client_ip)\
                / scapy.TCP(sport=self.router_port, dport=self.client_port, flags="PA",
                            seq=self.seq,
                            ack=self.ack)\
                / scapy.Raw(payload)
            scapy.send(p, verbose=0)
            self.seq += len(payload)


    def _split_payload(self, payload):
        """
        Receives a payload, splits it to a list of payloads,
        each with maximum length that scapy can send.

        Args:
            payload (str/bytes): TCP payload

        Returns:
            list: List of payloads
        """
        max_payload_length = 1400  # MTU = 1500
        payloads = [payload[i:i+max_payload_length]
                    for i in range(0, len(payload), max_payload_length)]
        return payloads
