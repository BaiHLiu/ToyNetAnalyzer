import pika
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.all import raw
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from scapy.layers.tls.all import TLS, TLSClientHello
from scapy.layers.dns import DNS

import json

import time
import threading

import parser.tcp
import parser.http
import parser.udp
import parser.icmp
import parser.dns
import es_conn
import functools
import logging
import sys
import os

THREAD_COUNT = 16
THREAD_HANDLE_COUNT = [0] * THREAD_COUNT

# 建立全局es连接
es = es_conn.ESPusher()
# 全局时间戳，用于计算每秒的数据包速率
global_timestamp = time.time()

# TCP 会话表，保存每个会话的状态
flow_table = {}
FLOW_TIMEOUT = 300  # 5分钟超时

def setup_logging():
    logging_level = logging.INFO
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s : %(message)s')
    formatter = logging.Formatter('%(asctime)s - %(levelname)s : %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    
    # 设置根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(logging_level)
    root_logger.addHandler(handler)
    
    # 设置第三方库的日志记录器级别为 WARNING
    logging.getLogger('elastic_transport').setLevel(logging.CRITICAL)
    logging.getLogger('pika').setLevel(logging.CRITICAL)
    logging.getLogger('urllib3').setLevel(logging.CRITICAL)

def create_rabbitmq_connection():
    """创建 RabbitMQ 连接和队列"""
    connection = pika.BlockingConnection(pika.ConnectionParameters(host='192.168.10.136'))
    channel = connection.channel()
    channel.queue_declare(queue='packet_queue')
    return connection, channel

def clean_flow_table():
    while True:
        cleaned_count = 0
        current_time = time.time()
        expired_flows = [flow_id for flow_id, flow in flow_table.items() if current_time - flow['last_seen'] > FLOW_TIMEOUT]
        for flow_id in expired_flows:
            del flow_table[flow_id]
            cleaned_count += 1
            
        logging.debug(f"Cleaned {cleaned_count} expired flows")
        time.sleep(60)  # 每分钟检查一次


def callback(ch, method, properties, body, worker_id):
    """从 RabbitMQ 消费数据并处理各种协议"""
    # 反序列化接收到的原始数据包
    data = json.loads(body)
    timestamp = data['timestamp']
    raw_packet_data = bytes.fromhex(data['packet_hex'])

    pkt_info = {
        'ip': None,
        'transport': {},
        'application': {},
        'timestamp': timestamp
    }
    
    # 解析L2层数据包
    raw_packet = scapy.Ether(raw_packet_data)
    flow_id = None

    transport_info = None
    
    # 解析IP层数据包
    if IP in raw_packet or IPv6 in raw_packet:
        ip_ip6_info = {
            'src_ip': raw_packet[IP].src if IP in raw_packet else raw_packet[IPv6].src,
            'dst_ip': raw_packet[IP].dst if IP in raw_packet else raw_packet[IPv6].dst,
            'ttl': raw_packet[IP].ttl if IP in raw_packet else raw_packet[IPv6].hlim,
            'protocol': raw_packet[IP].proto if IP in raw_packet else raw_packet[IPv6].nh,
            'length': raw_packet[IP].len if IP in raw_packet else raw_packet[IPv6].plen
        }
        pkt_info['ip'] = ip_ip6_info
        
        if TCP in raw_packet:
            transport_info = parser.tcp.track_tcp_flow(raw_packet, flow_table)

            if transport_info:
                # 解析应用层数据包
                if TLS in raw_packet or raw_packet.haslayer(HTTPRequest) or raw_packet.haslayer(HTTPResponse):
                    application_info = parser.http.parse_http(raw_packet)
                    pkt_info['application'] = application_info

        elif UDP in raw_packet:
            transport_info = parser.udp.parse_udp(raw_packet)

            if raw_packet.haslayer(DNS) and raw_packet[DNS].qr == 1:
                # 解析dns
                application_info = parser.dns.parse_dns(raw_packet)
                pkt_info['application'] = application_info

        elif ICMP in raw_packet:
            transport_info = parser.icmp.parse_icmp(raw_packet)
    
    # 有传输层信息
    if transport_info:
        pkt_info['transport'] = transport_info
    else:
        transport_info = {}

    # IP层成功解析则推送到ES
    if pkt_info['ip']:
        es.push_packet(pkt_info)
    else:
        logging.warning(f"Unknown packet: {raw_packet.summary()}")
    
    # 手动确认消息已处理完毕
    ch.basic_ack(delivery_tag=method.delivery_tag)
    THREAD_HANDLE_COUNT[worker_id] += 1

def consume_packets(thread_id):
    """从 RabbitMQ 队列中消费数据包"""
    connection, channel = create_rabbitmq_connection()
    
    callback_with_worker_id = functools.partial(callback, worker_id=thread_id)
    channel.basic_consume(queue='packet_queue', on_message_callback=callback_with_worker_id)
    
    logging.debug(f"Thread {thread_id} started!")
    channel.start_consuming()

def start_consumer_threads(thread_count):
    threads = []
    for _ in range(thread_count):
        thread = threading.Thread(target=consume_packets, args=(_,))
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()


def stats_collector():
    """统计每个线程处理的包数量"""
    global THREAD_HANDLE_COUNT
    while True:
        time.sleep(1)
        total_packets = sum(THREAD_HANDLE_COUNT)
        # sys.stdout.write("\033[1;1H\033[K")  # 将光标移动到第一行并清除行
        sys.stdout.write(f"\033[32mCurrent packet speed: {total_packets} pkt/s\033[0m\n")
        sys.stdout.flush()
        THREAD_HANDLE_COUNT = [0] * THREAD_COUNT

if __name__ == '__main__':
    os.system('clear')
    setup_logging()
    
    # 清理线程
    cleaner_thread = threading.Thread(target=clean_flow_table)
    cleaner_thread.daemon = True
    cleaner_thread.start()

    # 统计线程
    stats_thread = threading.Thread(target=stats_collector)
    stats_thread.daemon = True
    stats_thread.start()

    # 工作线程
    start_consumer_threads(THREAD_COUNT)

