import logging
from scapy.layers.inet import ICMP

def parse_icmp(raw_packet):
    """
    解析ICMP报文
    """
    transport_info = {}

    if raw_packet.haslayer(ICMP):
        icmp_layer = raw_packet[ICMP]
        transport_info['protocol'] = 'ICMP'
        transport_info['type'] = icmp_layer.type
        transport_info['code'] = icmp_layer.code
        transport_info['checksum'] = icmp_layer.chksum
        transport_info['id'] = icmp_layer.id
        transport_info['seq'] = icmp_layer.seq

        logging.debug(f"ICMP Packet: type={icmp_layer.type}, code={icmp_layer.code}, checksum={icmp_layer.chksum}, id={icmp_layer.id}, seq={icmp_layer.seq}")

    return transport_info