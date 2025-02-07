import logging
from scapy.layers.dns import DNS, DNSQR, DNSRR

def parse_dns(raw_packet):
    """
    解析DNS报文
    """
    application_info = {}
    if raw_packet.haslayer(DNS) and raw_packet[DNS].qr == 1:
        dns_layer = raw_packet[DNS]
        application_info['application_protocol'] = 'DNS'
        application_info['qname'] = dns_layer.qd.qname.decode() if dns_layer.qd else None  # 请求的域名
        application_info['qtype'] = dns_layer.qd.qtype if dns_layer.qd else None  # 请求的类型
        application_info['rcode'] = dns_layer.rcode  # 响应码
        application_info['answers'] = []  # 初始化回答列表

        for answer in dns_layer.an:
            # 判断data是bytes则转换为字符串
            data = None
            if hasattr(answer, 'rdata'):
                if isinstance(answer.rdata, bytes):
                    data = answer.rdata.decode()
                else:
                    data = answer.rdata

            # type转为可读的字符串，如'A'、'AAAA'等
            dns_answer = DNSRR()  # 创建 DNSRR 实例
            type_field = dns_answer.get_field('type')  # 获取 'type' 字段对象
            type_str = type_field.i2s.get(answer.type, "UNKNOWN")  # 转换为字符串类型

            application_info['answers'].append({
                'name': str(answer.rrname.decode()),
                'type': str(type_str),
                'data': str(data)
            })

            # print(application_info)

        # logging.debug(f"DNS Packet: qname={dns_layer.qd.qname.decode()}, qtype={dns_layer.qd.qtype}, rcode={dns_layer.rcode}")

    return application_info