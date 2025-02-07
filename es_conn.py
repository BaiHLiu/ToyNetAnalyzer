from elasticsearch import Elasticsearch
from datetime import datetime

ES_URL = "http://your-es-host:9200"
ES_USERNAME = "elastic"
ES_PASSWORD = "[very strong password]"
ES_INDEX = "packet_logs_1"

es_mapping = {
    "settings": {
        "index.default_pipeline": "geoip_pipeline",
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "properties": {
        "@timestamp": {"type": "date"},
        "geoip": {
        "properties": {
          "location": {
            "type": "geo_point"
          }
        }
        },
        "src_ip": {"type": "ip"},
        "dst_ip": {"type": "ip"},
        "ttl": {"type": "integer"},
        "protocol": {"type": "integer"},
        "src_port": {"type": "integer"},
        "dst_port": {"type": "integer"},
        "seq": {"type": "long"},
        "ack": {"type": "long"},
        "flags": {"type": "integer"},
        "transport_protocol": {"type": "keyword"},
        "flow_uid": {"type": "keyword"},
        "length": {"type": "integer"},
        "application_protocol": {"type": "keyword"},
        "dns": {
            "type": "object",
            "properties": {
                "qname": {"type": "keyword"},
                "qtype": {"type": "keyword"},
                "rcode": {"type": "keyword"},
                "answers": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "data": {"type": "keyword"}
                    }
                }
            }
        },
        "http": {
            "type": "object",
            "properties": {
            "method": {"type": "keyword"},
            "host": {"type": "keyword"},
            "path": {"type": "keyword"},
            "status": {"type": "integer"},
            "request_payload_length": {"type": "integer"},
            "request_payload": {"type": "text"},
            "response_payload_length": {"type": "integer"},
            "response_payload": {"type": "text"}
            }
        },
        "icmp" : {
            "type": "object",
            "properties": {
            "type": {"type": "integer"},
            "code": {"type": "integer"},
            "checksum": {"type": "integer"},
            "id": {"type": "integer"},
            "seq": {"type": "integer"}
            }
        },
        "sni_domain": {"type": "keyword"},
        'security_alert': {"type": "integer"}
        },
        
  }
}

class ESPusher:
    def __init__(self):
        self.es = Elasticsearch(ES_URL, http_auth=(ES_USERNAME, ES_PASSWORD))
        self.index_name = ES_INDEX
        print("[+] Successfully connected to Elasticsearch: ", ES_URL)
        print("[+] Using Index name: ", self.index_name)

        # 检查索引是否存在，不存在则创建
        if not self.es.indices.exists(index=self.index_name):
            self.es.indices.create(index=self.index_name, body=es_mapping)

        # 修改索引的mapping
        # self.es.indices.put_mapping(index=self.index_name, body=es_mapping)
    
    def push_packet(self, packet_json):
        """封装并推送完整的包信息到 Elasticsearch"""
        doc = {
            **self._wrap_ip_packet(packet_json.get('ip', {})),
            **self._wrap_transport_packet(packet_json.get('transport', {})),
            **self._wrap_application_packet(packet_json.get('application', {})),
            "@timestamp": packet_json.get('timestamp', datetime.utcnow().isoformat())
        }

        self._insert_to_es(doc)
    
    def _wrap_ip_packet(self, ip_info):
        return {
            'src_ip': ip_info.get('src_ip'),
            'dst_ip': ip_info.get('dst_ip'),
            'ttl': ip_info.get('ttl'),
            'protocol': ip_info.get('protocol')
        } if ip_info else {}

    def _wrap_transport_packet(self, transport_info):
        protocol = transport_info.get('protocol')
        if protocol == 'TCP':
            return {
                'src_port': transport_info.get('src_port'),
                'dst_port': transport_info.get('dst_port'),
                'seq': transport_info.get('seq'),
                'ack': transport_info.get('ack'),
                'flags': transport_info.get('flags'),
                'transport_protocol': 'TCP',
                'flow_uid': str(transport_info.get('flow_uid'))
            }
        elif protocol == 'UDP':
            return {
                'src_port': transport_info.get('src_port'),
                'dst_port': transport_info.get('dst_port'),
                'length': transport_info.get('length'),
                'transport_protocol': 'UDP'
            }
        
        elif protocol == 'ICMP':
            return {
                'icmp': {
                    'type': transport_info.get('type'),
                    'code': transport_info.get('code'),
                    'checksum': transport_info.get('checksum'),
                    'id': transport_info.get('id'),
                    'seq': transport_info.get('seq')
                },
                'transport_protocol': 'ICMP'
            }
        return {}

    def _wrap_application_packet(self, app_info):
        protocol = app_info.get('application_protocol')
        if protocol == 'DNS':
            return {
                'application_protocol': protocol,
                'dns': {
                    'qname': app_info.get('qname'),
                    'qtype': app_info.get('qtype'),
                    'rcode': app_info.get('rcode'),
                    'answers': app_info.get('answers')
                }
            }
        
        elif protocol in ('HTTP', 'HTTPS'):
            return {
                'application_protocol': protocol,
                'sni_domain': app_info.get('sni_domain'),
                'http': {
                    'method': app_info.get('http_method'),
                    'host': app_info.get('http_host'),
                    'path': app_info.get('http_path'),
                    'status': app_info.get('http_status'),
                    'request_payload_length': app_info.get('request_payload_length'),
                    'request_payload': app_info.get('request_payload'),
                    'response_payload_length': app_info.get('response_payload_length'),
                    'response_payload': app_info.get('response_payload')
                },
                'security_alert': app_info.get('security_alert', 0)
            }
        return {}

    def _insert_to_es(self, doc):
        try:
            self.es.index(index=self.index_name, body=doc)
        except Exception as e:
            print(f"Error inserting document: {e}")

# 使用示例
if __name__ == '__main__':
    # 初始化ESPusher对象
    pusher = ESPusher(es_host='localhost', es_port=9200, index_name='packet_logs')

    json_data = {
        'ip': {
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2',
            'ttl': 64,
            'protocol': 6  # TCP
        },
        'transport': {
            'protocol': 'TCP',
            'src_port': 1234,
            'dst_port': 80,
            'seq': 1001,
            'ack': 1002,
            'flags': 'S'
        },
        'application': {
            'protocol': 'HTTP',
            'method': 'GET',
            'host': 'example.com',
            'url': '/'
        }
    }

    # 将JSON数据推送到Elasticsearch
    pusher.push_packet(json_data)