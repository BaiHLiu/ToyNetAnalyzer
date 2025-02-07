from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
import uuid
import hashlib
import time
import secrets
import string
import logging

def generate_flow_id(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    else:
        raise ValueError("Packet is neither IPv4 nor IPv6")

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    else:
        raise ValueError("Packet is not TCP")

    # 生成整个会话的流ID，将src_ip、src_port、dst_ip、dst_port排序后哈希
    sorted_tuple = tuple(sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"]))
    flow_id = hashlib.md5(str(sorted_tuple).encode()).hexdigest()

    return flow_id

def track_tcp_flow(packet, flow_table):
    """追踪 TCP 会话，基于序列号和确认号重组数据"""
    if TCP in packet:
        flow_id = generate_flow_id(packet)
        current_time = time.time()

        if flow_id not in flow_table:
            chars = string.ascii_letters + string.digits
            random_token = ''.join(secrets.choice(chars) for _ in range(16))
            flow_table[flow_id] = {'packets': [], 'seq': None, 'ack': None, 'last_seen': current_time, 'flow_uid': random_token, 'closed': False}

        flow = flow_table[flow_id]
        flow["packets"].append(packet)
        flow["last_seen"] = current_time
        flow_uid = flow['flow_uid']

        # 更新序列号和确认号，进行流重组
        if flow["seq"] is None:  # 第一次抓到这个会话
            flow["seq"] = packet[TCP].seq
            flow["ack"] = packet[TCP].ack
        else:
            # 进行基于序列号的重组，可以加入更多逻辑处理重传或乱序
            if packet[TCP].seq >= flow["seq"]:
                flow["seq"] = packet[TCP].seq
            if packet[TCP].ack >= flow["ack"]:
                flow["ack"] = packet[TCP].ack

        # 检测连接结束状态
        if packet[TCP].flags & 0x01 or packet[TCP].flags & 0x04:  # FIN or RST
            if flow["closed"]:
                # print(f"Connection fully closed for flow ID: {flow_id}")
                ip_info = flow['packets'][0][IP] if IP in flow['packets'][0] else flow['packets'][0][IPv6]
                logging.debug(f"Flow {flow['flow_uid']} finished with {len(flow['packets'])} pkts! ({ip_info.src}:{ip_info.sport} <-> {ip_info.dst}:{ip_info.dport})")
                del flow_table[flow_id]
               
            else:
                flow["closed"] = True
                # print(f"Connection half-closed for flow ID: {flow_id}")

        transport_info = {
            'protocol': 'TCP',
            'src_port': packet[TCP].sport,
            'dst_port': packet[TCP].dport,
            'seq': flow['seq'],
            'ack': flow['ack'],
            'flags': int(packet[TCP].flags),
            'flow_uid': flow_uid
        }

        return transport_info
    return None