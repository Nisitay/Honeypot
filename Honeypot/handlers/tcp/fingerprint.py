"""
The p0f signature format -

ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass

ver     - IPv4 version
ittl    - Initial TTL used by the OS
olen    - Length of IPv4 options or IPv6 extension headers
mss     - Maximum segment size, if specified in TCP options
wsize   - TCP window size
scale   - Window scaling factor, if specified in TCP options
olayout - Layout and ordering of TCP options
quirks  - Quirks observed in IP or TCP headers
pclass  - Payload size classification
"""
import pydivert
import scapy.all as scapy

DB_FILE_PATH = r"Honeypot/common/p0f_db.fp"

# Translates Scapy TCP option name to p0f name
TCPOptions = {
    "MSS": "mss",
    "NOP": "nop",
    "WScale": "ws",
    "SAckOK": "sok",
    "SAck": "sack",
    "Timestamp": "ts",
}


def p0f(packet):
    """
    Passively fingerprint a Scapy/pydivert packet to calculate the most
    probable operating system of the packet source, based on various fields.

    Args:
        packet (scapy.Packet or pydivert.Packet): TCP/IP packet

    Returns:
        str: Matched OS
    """
    if isinstance(packet, pydivert.Packet):
        packet = scapy.IP(packet.ipv4.raw.tobytes())

    s = packet2sig(packet)
    for db_entry in db:
        b = db_entry[0]
        if ((s[6] == b[6]) and (s[0] == b[0] or b[0] == "*") and (s[1] == b[1])
                and (s[2] == b[2]) and (s[3] == b[3] or b[3] == "*")
                and (s[4] == b[4] or "*" in b[4])
                and (s[5] == b[5]) and (s[7] == b[7]) and (s[8] == b[8])):
            return db_entry[1]
    return "Unknown OS"


def packet2sig(packet: scapy.Packet):
    """
    Converts a TCP/IP Scapy packet to a p0f signature.
    A p0f signature is managed as a tuple, according to
    the p0f signature format.

    Args:
        packet (scapy.Packet): TCP/IP Scapy packet

    Returns:
        tuple: p0f signature
    """
    ver = packet[scapy.IP].version
    ittl = get_initial_ttl(packet[scapy.IP].ttl)
    olen = len(packet[scapy.IP].options)

    tcp_options = packet[scapy.TCP].options
    tcp_options_dict = dict(tcp_options)

    mss = tcp_options_dict.get("MSS", 0)
    wsize = packet[scapy.TCP].window
    scale = tcp_options_dict.get("WScale", 0)

    olayout_lst = [TCPOptions[field_name] for field_name, value in tcp_options]
    olayout = ",".join(olayout_lst)
    if packet[scapy.IP].flags.DF and packet[scapy.IP].id:
        quirks = "df,id+"
    else:
        quirks = ""
    pclass = len(packet[scapy.TCP].payload)

    sig = (ver, ittl, olen, mss, wsize, scale, olayout, quirks, pclass)
    return tuple(str(field) for field in sig)


def get_initial_ttl(ttl):
    """
    Returns the most likely initial ttl from a
    packet ttl

    Args:
        ttl (int): Packet ttl

    Returns:
        int: Initial ttl
    """
    initial_ttls = [32, 64, 128, 255]
    closest_ttl = min(filter(lambda x: x >= ttl, initial_ttls))
    return closest_ttl


def read_db(file_path):
    """
    Reads the database file into a list.
    Each list item consists of ((sig), label)
    where 'label' is the OS name and 'sig' is the signature

    Args:
        file_path (str): Database text file path.

    Returns:
        list: p0f Database
    """
    db = []
    label_name = ""
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:  # Empty line
                continue
            if ":" in line:  # Line with signature
                sig = line.split(":")
                sig[4:4] = sig[4].split(",")
                del sig[6]
                db.append((tuple(sig), label_name))
            else:  # Line with a label name for next signatures
                label_name = line.strip()
    return db

db = read_db(DB_FILE_PATH)