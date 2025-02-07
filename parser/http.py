from scapy.layers.tls.extensions import TLS_Ext_ServerName
from scapy.layers.tls.all import TLS, TLSClientHello
import logging
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.all import Raw
from security import sql_injection
from urllib.parse import unquote

def extract_sni(packet):
    """提取并打印数据包中的 SNI 信息"""
    # if packet.haslayer(scapy.Raw) and TLS in packet:
    if TLS in packet:
        tls_layer = packet[TLS]
        # 如果是ClientHello，则提取SNI
        if tls_layer.haslayer(TLSClientHello):
            logging.debug(f"TLS ClientHello: {tls_layer.summary()}")
            tls_ch = tls_layer[TLSClientHello]
            if tls_ch.haslayer(TLS_Ext_ServerName):
                sni = tls_ch[TLS_Ext_ServerName].servernames[0].servername.decode()
                logging.debug(f"Extracted SNI: {sni}")
                return sni
            
    return None

def parse_http(raw_packet):

    application_info = {}
    security_flag = 0

    sni = extract_sni(raw_packet)
    if sni:
        application_info["sni_domain"] = sni
        application_info["application_protocol"] = "HTTPS"

    if raw_packet.haslayer(HTTPRequest):
        http_layer = raw_packet[HTTPRequest]
        logging.debug(f"HTTP Request: {http_layer.Method.decode()} {http_layer.Host.decode()}{http_layer.Path.decode()}")
        http_path = unquote(http_layer.Path.decode())

        application_info["application_protocol"] = "HTTP"
        application_info["http_method"] = http_layer.Method.decode()
        application_info["http_host"] = http_layer.Host.decode()
        application_info["http_path"] = http_path
        
        # get参数安全检查
        if sql_injection.check_for_sql_injection(http_path):
            security_flag = 1
            logging.warning(f"SQL Injection detected in HTTP Path: {http_path}")

        if raw_packet.haslayer(Raw):
            application_info['request_payload_lengh'] = len(raw_packet[Raw].load)
            application_info['request_payload'] = raw_packet[Raw].load.hex()
            logging.debug(f"HTTP Request Payload Length: {len(raw_packet[Raw].load)}")
            # 尝试解析为文本，检查安全问题
            try:
                if sql_injection.check_for_sql_injection(raw_packet[Raw].load.decode()):
                    security_flag = 1
                    logging.warning(f"SQL Injection detected in HTTP Request Payload: {raw_packet[Raw].load.decode()}")
            except UnicodeDecodeError:
                pass

    elif raw_packet.haslayer(HTTPResponse):
        http_layer = raw_packet[HTTPResponse]
        logging.debug(f"HTTP Response: {http_layer.Status_Code.decode()}")
        application_info["application_protocol"] = "HTTP"
        application_info["http_status"] = http_layer.Status_Code.decode()
        if raw_packet.haslayer(Raw):
            application_info['response_payload_length'] = len(raw_packet[Raw].load)
            application_info['response_payload'] = raw_packet[Raw].load.hex()
            logging.debug(f"HTTP Response Payload Length: {len(raw_packet[Raw].load)}")

    application_info["security_alert"] = security_flag
    return application_info