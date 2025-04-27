import re
import time
from pathlib import Path

class IDS:
    SIGNATURES = [
        (r"Failed password for .* from <HOST>", "SSH Brute Force Attempt"),
        (r"GET .*wp-login.php", "WordPress Login Attempt"),
        (r"union.*select", "SQL Injection Attempt"),
        (r"<script>.*</script>", "XSS Attempt")
    ]

    def __init__(self, log_path='/var/log/auth.log'):
        self.log_path = Path(log_path)
        self.running = False

    def _tail_log(self):
        with open(self.log_path, 'r') as f:
            f.seek(0, 2)
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line

    def _analyze_line(self, line):
        alerts = []
        for pattern, description in self.SIGNATURES:
            if re.search(pattern, line, re.IGNORECASE):
                alerts.append({
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'description': description,
                    'log_entry': line.strip()
                })
        return alerts

    def start_monitoring(self):
        self.running = True
        for line in self._tail_log():
            alerts = self._analyze_line(line)
            if alerts:
                # Implement real-time alerting here
                print(f"ALERT: {alerts}")

    def stop_monitoring(self):
        self.running = False
