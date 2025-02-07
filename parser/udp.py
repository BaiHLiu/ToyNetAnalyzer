import logging
from scapy.layers.inet import UDP

def parse_udp(raw_packet):
    """
    解析UDP报文
    """
    transport_info = {}

    if raw_packet.haslayer(UDP):
        udp_layer = raw_packet[UDP]
        transport_info['protocol'] = 'UDP'
        transport_info['src_port'] = udp_layer.sport
        transport_info['dst_port'] = udp_layer.dport
        transport_info['checksum'] = udp_layer.chksum
        transport_info['length'] = udp_layer.len

        logging.debug(f"UDP Packet: src_port={udp_layer.sport}, dst_port={udp_layer.dport}, checksum={udp_layer.chksum}")

    return transport_info