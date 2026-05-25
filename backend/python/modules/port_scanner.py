import socket
import concurrent.futures
from ipaddress import ip_address

class PortScanner:
    def __init__(self, target, port_range='1-1024'):
        self.target = target
        self.port_range = self._parse_range(port_range)
        self.open_ports = []
        self.scanned = 0
        self.total = len(self.port_range)
        self.running = False

    def _parse_range(self, port_range):
        try:
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                return range(start, end+1)
            return [int(port_range)]
        except:
            return range(1, 1025)

    def _validate_target(self):
        try:
            ip_address(self.target)
            return True
        except:
            try:
                socket.gethostbyname(self.target)
                return True
            except:
                return False

    def _scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((self.target, port))
                self.open_ports.append(port)
        except:
            pass
        finally:
            self.scanned += 1

    def run(self):
        if not self._validate_target():
            return {'error': 'Invalid target'}
        
        self.running = True
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(self._scan_port, self.port_range)
        self.running = False

    def get_progress(self):
        return {
            'scanned': self.scanned,
            'total': self.total,
            'open_ports': self.open_ports,
            'progress': (self.scanned / self.total) * 100 if self.total > 0 else 0
        }
