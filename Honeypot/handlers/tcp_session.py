import scapy.all as scapy
import random

MAX_SEQUENCE_NUM = 4294967295
MAX_WINDOW_SIZE = 5900


class TCPSession():
    """
    Handles a TCP session between a source and a target, using scapy
    """
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = 0
        self.ack = 0
        self.window = 0
        self.s = scapy.conf.L3socket()
        self.ip = scapy.IP(src=self.src_ip, dst=self.dst_ip)

    def connect(self):
        """
        Connects to the target - sends syn packet, waits for syn ack,
        then returns ack to finish handshake
        """
        self.seq = random.randint(0, MAX_SEQUENCE_NUM)
        syn = self.ip / scapy.TCP(sport=self.src_port, dport=self.dst_port,
                                  flags="S", seq=self.seq, ack=self.ack,
                                  options=[("MSS", 1460)])
        self.seq += 1
        syn_ack = self.s.sr1(syn, verbose=0)

        self.ack = syn_ack[scapy.TCP].seq + 1
        self._send_ack()

    def register_syn_ack(self, syn_ack_packet):
        """
        Receives a syn-ack packet and finishes the handshake
        (returns an ack packet)

        Args:
            syn_ack_packet (pydivert.Packet): a pydivert packet
        """
        self.ack = syn_ack_packet.tcp.seq_num + 1
        self._send_ack()

    def register_syn(self, syn_packet):
        """
        Receives a syn packet and accepts the connection
        (returns a syn-ack packet)

        Args:
            syn_packet (pydivert.Packet): a pydivert packet
        """
        self.ack = syn_packet.tcp.seq_num + 1
        self.seq = random.randint(0, MAX_SEQUENCE_NUM)
        syn_ack = self.ip / scapy.TCP(sport=self.src_port, dport=self.dst_port,
                                      flags="SA", seq=self.seq, ack=self.ack,
                                      options=[("MSS", 1460)])
        self.s.send(syn_ack)
        self.seq += 1

    def disconnect(self):
        """
        Disconnects from the target (sends fin-ack/ack)
        """
        fin_ack = self.ip / scapy.TCP(sport=self.src_port, dport=self.dst_port,
                                      flags="FA", seq=self.seq, ack=self.ack)
        self.s.send(fin_ack)
        self.seq += 1
        self.ack += 1
        self._send_ack()
        self.s.close()

    def register_payload_packet(self, payload_packet):
        """
        Receives a packet with payload and returns ack packet

        Args:
            payload_packet (pydivert.Packet): a pydivert packet
        """
        self.ack += len(payload_packet.payload)
        self.window += len(payload_packet.payload)
        if len(payload_packet.payload) < 1460 or self.window >= MAX_WINDOW_SIZE:
            self._send_ack()
            self.window = 0

    def sendall(self, payloads):
        """
        Receives a list of payloads to send, and sends them

        Args:
            payloads (list): list of bytes/strings
        """
        for payload in payloads:
            self.send(payload)

    def send(self, payload):
        """
        Receives a payload and sends it to the client.
        Payloads bigger than MTU will be split to multiple packets

        Args:
            payload (str/bytes): a TCP payload
        """
        for payload in self._split_payload(payload):
            p = self.ip / scapy.TCP(sport=self.src_port, dport=self.dst_port,
                                    flags="PA",
                                    seq=self.seq,
                                    ack=self.ack) / scapy.Raw(payload)
            self.s.send(p)
            self.seq += len(payload)

    def _send_ack(self):
        ack = self.ip / scapy.TCP(sport=self.src_port, dport=self.dst_port,
                                  flags="A", seq=self.seq, ack=self.ack)
        self.s.send(ack)

    def _split_payload(self, payload):
        """
        Receives a payload, splits it to a list of payloads,
        each with maximum length that can be sent.

        Args:
            payload (str/bytes): TCP payload

        Returns:
            generator: Generator of payloads
        """
        max_payload_length = 1450  # MTU dependent
        return (payload[i:i+max_payload_length]
                for i in range(0, len(payload), max_payload_length))
