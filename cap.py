import threading
import pika
from scapy.all import sniff, raw
from datetime import datetime
import json

# RabbitMQ连接参数
RABBITMQ_HOST = 'your-mq-host'
RABBITMQ_QUEUE = 'packet_queue'
INTERFACES = ['en7', 'en0']  # 列表存储多个网卡接口
BPF_FILTER = 'tcp port 80 or tcp port 8090 or tcp port 443 or tcp port 1443 or udp port 53 or icmp'

# 创建RabbitMQ连接和通道
connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
channel = connection.channel()
channel.queue_declare(queue=RABBITMQ_QUEUE)

# 定义一个回调函数来处理捕获的数据包
def packet_callback(packet):
    timestamp = datetime.utcnow().isoformat()
    packet_data = raw(packet)
    
    data = {
        'timestamp': timestamp,
        'packet_hex': packet_data.hex()
    }

    # 将数据包推送到RabbitMQ
    channel.basic_publish(exchange='', routing_key=RABBITMQ_QUEUE, body=json.dumps(data))
    print(f"Packet sent to RabbitMQ: {packet.summary()} at {timestamp}")

# 定义一个函数来启动数据包捕获
def start_sniffing(interface):
    sniff(iface=interface, filter=BPF_FILTER, prn=packet_callback)

# 创建并启动线程来运行数据包捕获
threads = []
for interface in INTERFACES:
    sniff_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniff_thread.start()
    threads.append(sniff_thread)

# 保持主线程运行
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping sniffing...")
    connection.close()
    for thread in threads:
        thread.join()