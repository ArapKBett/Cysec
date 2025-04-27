from scapy.all import sniff, conf
from scapy.layers import http
import json
import time

class PacketSniffer:
    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self.stats = {
            'start_time': time.time(),
            'total_packets': 0,
            'protocols': {},
            'http_requests': [],
            'suspicious': []
        }

    def _packet_handler(self, packet):
        self.stats['total_packets'] += 1
        
        # Layer analysis
        if packet.haslayer('IP'):
            self.stats['protocols']['IP'] = self.stats['protocols'].get('IP', 0) + 1
        if packet.haslayer('TCP'):
            self.stats['protocols']['TCP'] = self.stats['protocols'].get('TCP', 0) + 1
        if packet.haslayer('UDP'):
            self.stats['protocols']['UDP'] = self.stats['protocols'].get('UDP', 0) + 1

        # HTTP analysis
        if packet.haslayer(http.HTTPRequest):
            http_layer = packet.getlayer(http.HTTPRequest)
            entry = {
                'method': http_layer.Method.decode(),
                'host': http_layer.Host.decode(),
                'path': http_layer.Path.decode(),
                'user_agent': http_layer.User_Agent.decode() if http_layer.User_Agent else None
            }
            self.stats['http_requests'].append(entry)

        # Threat detection
        if packet.haslayer('Raw'):
            payload = packet['Raw'].load.decode(errors='ignore')
            if any(keyword in payload.lower() for keyword in ['select', 'union', 'drop', '1=1']):
                self.stats['suspicious'].append({
                    'src': packet['IP'].src if packet.haslayer('IP') else 'N/A',
                    'dst': packet['IP'].dst if packet.haslayer('IP') else 'N/A',
                    'payload_snippet': payload[:200]
                })

    def start(self):
        self.running = True
        sniff(iface=self.interface, prn=self._packet_handler, store=0, stop_filter=lambda _: not self.running)

    def stop(self):
        self.running = False
        self.stats['duration'] = time.time() - self.stats['start_time']
        return self.stats

    def get_stats(self):
        return self.stats
