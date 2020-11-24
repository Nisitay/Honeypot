
def fingerprint(packet):
    """
    Calculates the most probable operating system of the packet source,
    based on the packets' TTL and window size.

    Args:
        packet (pydivert packet):

    Returns:
        str: A string of the most probable OS
    """
    ttl = packet.ipv4.ttl
    window_size = packet.tcp.window_size
    closest_ttl = min(filter(lambda x: x >= ttl, [64, 128, 255]))  # Closest original ttl
    os_finder = {
        64:{
            5720: "Google's customized Linux",
            5840: "Linux (kernel 2.4 and 2.6)",
            16384: "OpenBSD, AIX 4.3",
            32120: "Linux (kernel 2.2)",
            65535: "FreeBSD"
        },
        128:{
            8192: "Windows 7, Vista, and Server 2008",
            16384: "Windows 2000",
            65535: "Windows XP"
        },
        255:{
            4128: "Cisco Router (IOS 12.4)",
            8760: "Solaris 7"
        }
    }

    probable_os = os_finder.get(closest_ttl).get(window_size)
    if probable_os is None: probable_os = "Unknown OS"
    return probable_os
   