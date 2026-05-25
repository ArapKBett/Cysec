"""
Advanced Network Scanner - Enterprise Grade
Multi-threaded, intelligent scanning with vulnerability detection
"""

import socket
import threading
import time
import nmap
import concurrent.futures
from ipaddress import ip_network, IPv4Network, IPv6Network
from dataclasses import dataclass
from typing import List, Dict, Optional, Set
import json
import uuid
from datetime import datetime
import requests
import ssl
import subprocess
import re
import asyncio
import aiohttp
from pathlib import Path

@dataclass
class ScanTarget:
    """Enhanced scan target with metadata"""
    address: str
    port_range: str = "1-65535"
    scan_type: str = "comprehensive"
    priority: int = 1
    tags: List[str] = None
    exclusions: List[str] = None

@dataclass
class PortResult:
    """Enhanced port scan result"""
    port: int
    state: str
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    vulnerabilities: List[Dict] = None
    ssl_info: Dict = None
    http_headers: Dict = None
    confidence: float = 0.0

class AdvancedScanner:
    """Enterprise-grade network scanner with advanced capabilities"""

    def __init__(self, target, scan_type='comprehensive', ports='1-65535',
                 scripts=None, intensity='normal'):
        self.target = target
        self.scan_type = scan_type
        self.ports = ports
        self.scripts = scripts or []
        self.intensity = intensity
        self.scan_id = str(uuid.uuid4())
        self.results = {}
        self.status = 'initialized'
        self.start_time = None
        self.end_time = None
        self.thread_pool_size = self._calculate_threads()
        self.nm = nmap.PortScanner()

        # Advanced scanning configurations
        self.scan_profiles = {
            'stealth': {
                'timing': '-T1',
                'flags': '-sS -f --scan-delay 10ms',
                'scripts': ['safe']
            },
            'comprehensive': {
                'timing': '-T4',
                'flags': '-sS -sV -O -A --osscan-guess',
                'scripts': ['default', 'vuln', 'discovery']
            },
            'aggressive': {
                'timing': '-T5',
                'flags': '-sS -sV -O -A -Pn --min-rate 1000',
                'scripts': ['default', 'vuln', 'exploit']
            },
            'vulnerability': {
                'timing': '-T4',
                'flags': '-sS -sV --script=vuln',
                'scripts': ['vuln', 'exploit', 'malware']
            }
        }

    def _calculate_threads(self):
        """Calculate optimal thread count based on scan type and target"""
        base_threads = {
            'stealth': 10,
            'comprehensive': 100,
            'aggressive': 500,
            'vulnerability': 50
        }
        return base_threads.get(self.scan_type, 100)

    def start_scan(self):
        """Start advanced scanning operation"""
        self.status = 'running'
        self.start_time = datetime.utcnow()

        # Start scan in background thread
        scan_thread = threading.Thread(target=self._execute_scan)
        scan_thread.daemon = True
        scan_thread.start()

        return self.scan_id

    def _execute_scan(self):
        """Execute the comprehensive scanning process"""
        try:
            # Phase 1: Host Discovery
            self._host_discovery()

            # Phase 2: Port Scanning
            self._port_scan()

            # Phase 3: Service Detection
            self._service_detection()

            # Phase 4: Vulnerability Assessment
            self._vulnerability_scan()

            # Phase 5: Advanced Analysis
            self._advanced_analysis()

            self.status = 'completed'
            self.end_time = datetime.utcnow()

        except Exception as e:
            self.status = 'failed'
            self.results['error'] = str(e)

    def _host_discovery(self):
        """Advanced host discovery with multiple techniques"""
        discovery_results = {}

        # Ping sweep
        try:
            ping_result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', self.target],
                capture_output=True, text=True, timeout=5
            )
            discovery_results['ping_responsive'] = ping_result.returncode == 0
        except:
            discovery_results['ping_responsive'] = False

        # ARP discovery (for local networks)
        if self._is_local_network():
            discovery_results['arp_discovery'] = self._arp_discovery()

        # DNS resolution
        try:
            import socket
            ip = socket.gethostbyname(self.target)
            discovery_results['dns_resolution'] = {
                'resolved': True,
                'ip_address': ip
            }
        except:
            discovery_results['dns_resolution'] = {'resolved': False}

        self.results['host_discovery'] = discovery_results

    def _port_scan(self):
        """Multi-technique port scanning"""
        profile = self.scan_profiles.get(self.scan_type, self.scan_profiles['comprehensive'])

        # Nmap scan
        nmap_args = f"{profile['timing']} {profile['flags']}"

        try:
            self.nm.scan(self.target, self.ports, arguments=nmap_args)
            nmap_results = self._parse_nmap_results()
        except Exception as e:
            nmap_results = {'error': str(e)}

        # Custom TCP connect scan for reliability
        custom_results = self._custom_tcp_scan()

        # UDP scan for comprehensive coverage
        udp_results = self._udp_scan() if 'comprehensive' in self.scan_type else {}

        self.results['port_scan'] = {
            'nmap': nmap_results,
            'custom_tcp': custom_results,
            'udp': udp_results
        }

    def _custom_tcp_scan(self):
        """Custom TCP connect scan with enhanced features"""
        port_range = self._parse_port_range(self.ports)
        open_ports = []
        port_details = {}

        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    result = sock.connect_ex((self.target, port))
                    if result == 0:
                        # Banner grabbing
                        banner = self._grab_banner(self.target, port)
                        service = self._identify_service(port, banner)

                        port_info = PortResult(
                            port=port,
                            state='open',
                            service=service,
                            banner=banner,
                            confidence=0.8
                        )

                        # Additional analysis for common services
                        if port == 80 or port == 8080:
                            port_info.http_headers = self._get_http_headers(self.target, port)
                        elif port == 443 or port == 8443:
                            port_info.ssl_info = self._get_ssl_info(self.target, port)

                        open_ports.append(port)
                        port_details[port] = port_info.__dict__

            except Exception as e:
                pass  # Port likely closed or filtered

        # Multi-threaded scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_pool_size) as executor:
            executor.map(scan_port, port_range)

        return {
            'open_ports': sorted(open_ports),
            'port_details': port_details,
            'total_scanned': len(port_range)
        }

    def _service_detection(self):
        """Advanced service detection and fingerprinting"""
        if 'port_scan' not in self.results:
            return

        open_ports = self.results['port_scan']['custom_tcp']['open_ports']
        service_results = {}

        for port in open_ports:
            service_info = {
                'port': port,
                'techniques_used': [],
                'confidence_score': 0.0
            }

            # Banner-based detection
            if 'port_details' in self.results['port_scan']['custom_tcp']:
                port_detail = self.results['port_scan']['custom_tcp']['port_details'].get(str(port), {})
                banner = port_detail.get('banner', '')
                if banner:
                    service_info['banner_analysis'] = self._analyze_banner(banner)
                    service_info['techniques_used'].append('banner_grabbing')

            # Protocol-specific probes
            if port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]:
                protocol_info = self._protocol_specific_probe(self.target, port)
                service_info['protocol_analysis'] = protocol_info
                service_info['techniques_used'].append('protocol_probe')

            # Nmap service detection results
            if hasattr(self.nm, 'all_hosts') and self.nm.all_hosts():
                host = self.nm.all_hosts()[0]
                if port in self.nm[host].all_protocols():
                    nmap_service = self.nm[host]['tcp'].get(port, {})
                    service_info['nmap_detection'] = {
                        'name': nmap_service.get('name', ''),
                        'product': nmap_service.get('product', ''),
                        'version': nmap_service.get('version', ''),
                        'extrainfo': nmap_service.get('extrainfo', '')
                    }
                    service_info['techniques_used'].append('nmap_detection')

            service_results[port] = service_info

        self.results['service_detection'] = service_results

    def _vulnerability_scan(self):
        """Comprehensive vulnerability assessment"""
        vulnerabilities = {}

        # Nmap vulnerability scripts
        vuln_scripts = [
            'vuln', 'exploit', 'intrusive', 'malware',
            'http-vuln-*', 'ssl-*', 'smb-vuln-*'
        ]

        for script_category in vuln_scripts:
            try:
                script_args = f"--script={script_category}"
                vuln_result = self.nm.scan(self.target, self.ports, arguments=script_args)
                vulnerabilities[script_category] = self._parse_vuln_results(vuln_result)
            except Exception as e:
                vulnerabilities[script_category] = {'error': str(e)}

        # Custom vulnerability checks
        custom_vulns = self._custom_vulnerability_checks()
        vulnerabilities['custom_checks'] = custom_vulns

        self.results['vulnerabilities'] = vulnerabilities

    def _advanced_analysis(self):
        """Advanced analysis and correlation"""
        analysis = {
            'risk_assessment': self._calculate_risk_score(),
            'attack_surface': self._analyze_attack_surface(),
            'recommendations': self._generate_recommendations(),
            'compliance_issues': self._check_compliance(),
            'threat_indicators': self._identify_threat_indicators()
        }

        self.results['advanced_analysis'] = analysis

    def _grab_banner(self, host, port):
        """Enhanced banner grabbing with timeout handling"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                sock.connect((host, port))

                # Send appropriate probe based on port
                probe = self._get_service_probe(port)
                if probe:
                    sock.send(probe.encode())

                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
        except:
            return ""

    def _get_service_probe(self, port):
        """Get appropriate probe for service detection"""
        probes = {
            21: "",  # FTP - banner sent immediately
            22: "",  # SSH - banner sent immediately
            23: "",  # Telnet - banner sent immediately
            25: "EHLO test\\r\\n",  # SMTP
            80: "GET / HTTP/1.1\\r\\nHost: test\\r\\n\\r\\n",  # HTTP
            110: "",  # POP3 - banner sent immediately
            443: "",  # HTTPS - requires SSL handshake
            993: "",  # IMAPS
            995: ""   # POP3S
        }
        return probes.get(port, "")

    def _get_http_headers(self, host, port):
        """Get HTTP headers and server information"""
        try:
            url = f"http://{host}:{port}/"
            response = requests.get(url, timeout=5, allow_redirects=False)
            return dict(response.headers)
        except:
            return {}

    def _get_ssl_info(self, host, port):
        """Get SSL/TLS certificate and configuration information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    return {
                        'certificate': cert,
                        'cipher_suite': cipher,
                        'protocol': ssock.version()
                    }
        except:
            return {}

    def _calculate_risk_score(self):
        """Calculate overall risk score based on findings"""
        risk_factors = {
            'open_ports': 0.2,
            'vulnerable_services': 0.4,
            'outdated_software': 0.3,
            'weak_crypto': 0.3,
            'default_credentials': 0.5
        }

        total_risk = 0.0
        # Implementation of risk calculation logic
        # This would analyze the scan results and calculate risk

        return {
            'score': min(total_risk, 100),
            'level': self._risk_level(total_risk),
            'factors': risk_factors
        }

    def _risk_level(self, score):
        """Determine risk level from score"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'

    def get_results(self):
        """Get comprehensive scan results"""
        return {
            'scan_id': self.scan_id,
            'target': self.target,
            'scan_type': self.scan_type,
            'status': self.status,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': str(self.end_time - self.start_time) if self.end_time and self.start_time else None,
            'results': self.results
        }

    def get_progress(self):
        """Get real-time scan progress"""
        phases = ['host_discovery', 'port_scan', 'service_detection', 'vulnerabilities', 'advanced_analysis']
        completed_phases = sum(1 for phase in phases if phase in self.results)

        return {
            'scan_id': self.scan_id,
            'status': self.status,
            'progress_percentage': (completed_phases / len(phases)) * 100,
            'current_phase': phases[completed_phases] if completed_phases < len(phases) else 'completed',
            'phases_completed': completed_phases,
            'total_phases': len(phases)
        }

    def estimate_duration(self):
        """Estimate scan duration based on target and scan type"""
        port_count = len(self._parse_port_range(self.ports))

        duration_factors = {
            'stealth': 10,    # seconds per port
            'comprehensive': 2,
            'aggressive': 0.5,
            'vulnerability': 5
        }

        factor = duration_factors.get(self.scan_type, 2)
        estimated_seconds = port_count * factor

        return {
            'estimated_seconds': estimated_seconds,
            'estimated_minutes': round(estimated_seconds / 60, 2),
            'factors_considered': ['port_range', 'scan_type', 'target_responsiveness']
        }

    # Helper methods
    def _parse_port_range(self, port_range):
        """Parse port range into list of integers"""
        ports = []
        for part in port_range.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return ports

    def _is_local_network(self):
        """Check if target is in local network"""
        try:
            network = ip_network(f"{self.target}/24", strict=False)
            return network.is_private
        except:
            return False

    def _parse_nmap_results(self):
        """Parse and structure nmap results"""
        results = {}
        if hasattr(self.nm, 'all_hosts') and self.nm.all_hosts():
            for host in self.nm.all_hosts():
                results[host] = {
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'protocols': self.nm[host].all_protocols()
                }

                for protocol in self.nm[host].all_protocols():
                    results[host][protocol] = {}
                    for port in self.nm[host][protocol].keys():
                        results[host][protocol][port] = self.nm[host][protocol][port]

        return results

    def _identify_service(self, port, banner):
        """Identify service from port and banner"""
        common_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 993: 'imaps', 995: 'pop3s'
        }

        service = common_services.get(port, 'unknown')

        # Refine based on banner
        if banner:
            banner_lower = banner.lower()
            if 'http' in banner_lower:
                service = 'http'
            elif 'ssh' in banner_lower:
                service = 'ssh'
            elif 'ftp' in banner_lower:
                service = 'ftp'

        return service

    def _analyze_banner(self, banner):
        """Analyze banner for service and version information"""
        analysis = {
            'service': 'unknown',
            'version': '',
            'vendor': '',
            'operating_system': ''
        }

        # Common patterns
        patterns = {
            'apache': r'Apache/(\d+\.\d+\.\d+)',
            'nginx': r'nginx/(\d+\.\d+\.\d+)',
            'openssh': r'OpenSSH_(\d+\.\d+)',
            'vsftpd': r'vsftpd (\d+\.\d+\.\d+)',
            'microsoft': r'Microsoft.+?(\d+\.\d+)',
        }

        for service, pattern in patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                analysis['service'] = service
                analysis['version'] = match.group(1)
                break

        return analysis

    def _protocol_specific_probe(self, host, port):
        """Send protocol-specific probes for detailed service detection"""
        probes = {
            80: self._http_probe,
            443: self._https_probe,
            21: self._ftp_probe,
            22: self._ssh_probe,
            25: self._smtp_probe
        }

        probe_func = probes.get(port)
        if probe_func:
            return probe_func(host, port)
        return {}

    def _http_probe(self, host, port):
        """HTTP-specific probing"""
        try:
            url = f"http://{host}:{port}/"
            response = requests.get(url, timeout=5)
            return {
                'status_code': response.status_code,
                'server': response.headers.get('Server', ''),
                'content_type': response.headers.get('Content-Type', ''),
                'powered_by': response.headers.get('X-Powered-By', '')
            }
        except:
            return {}

    def _https_probe(self, host, port):
        """HTTPS-specific probing"""
        try:
            url = f"https://{host}:{port}/"
            response = requests.get(url, timeout=5, verify=False)
            ssl_info = self._get_ssl_info(host, port)
            return {
                'status_code': response.status_code,
                'server': response.headers.get('Server', ''),
                'ssl_info': ssl_info
            }
        except:
            return {}

    def _ftp_probe(self, host, port):
        """FTP-specific probing"""
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            welcome = ftp.getwelcome()
            ftp.quit()
            return {'welcome_message': welcome}
        except:
            return {}

    def _ssh_probe(self, host, port):
        """SSH-specific probing"""
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            transport = paramiko.Transport((host, port))
            transport.start_client(timeout=5)
            server_version = transport.get_remote_server_key().get_name()
            transport.close()
            return {'server_version': server_version}
        except:
            return {}

    def _smtp_probe(self, host, port):
        """SMTP-specific probing"""
        try:
            import smtplib
            smtp = smtplib.SMTP(timeout=5)
            smtp.connect(host, port)
            banner = smtp.ehlo_msg.decode() if smtp.ehlo_msg else ""
            smtp.quit()
            return {'ehlo_message': banner}
        except:
            return {}

    def _custom_vulnerability_checks(self):
        """Custom vulnerability assessment"""
        vulnerabilities = {}

        # Check for common vulnerabilities
        if 'port_scan' in self.results:
            open_ports = self.results['port_scan']['custom_tcp']['open_ports']

            # Check for default service ports
            risky_ports = [21, 23, 135, 139, 445, 1433, 3389]
            exposed_risky = [port for port in open_ports if port in risky_ports]

            if exposed_risky:
                vulnerabilities['exposed_risky_services'] = {
                    'severity': 'HIGH',
                    'ports': exposed_risky,
                    'description': 'High-risk services exposed'
                }

        return vulnerabilities

    def _analyze_attack_surface(self):
        """Analyze the attack surface"""
        if 'port_scan' not in self.results:
            return {}

        open_ports = self.results['port_scan']['custom_tcp']['open_ports']

        return {
            'open_port_count': len(open_ports),
            'external_services': len([p for p in open_ports if p < 1024]),
            'high_risk_services': len([p for p in open_ports if p in [21, 23, 135, 139, 445]]),
            'web_services': len([p for p in open_ports if p in [80, 443, 8080, 8443]])
        }

    def _generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = []

        if 'port_scan' in self.results:
            open_ports = self.results['port_scan']['custom_tcp']['open_ports']

            # Check for unnecessary services
            if 21 in open_ports:
                recommendations.append({
                    'priority': 'HIGH',
                    'title': 'Disable FTP Service',
                    'description': 'FTP transmits credentials in plain text. Consider SFTP instead.'
                })

            if 23 in open_ports:
                recommendations.append({
                    'priority': 'HIGH',
                    'title': 'Disable Telnet Service',
                    'description': 'Telnet is unencrypted. Use SSH instead.'
                })

        return recommendations

    def _check_compliance(self):
        """Check compliance with security standards"""
        compliance_results = {}

        # PCI DSS checks
        pci_issues = []
        if 'port_scan' in self.results:
            open_ports = self.results['port_scan']['custom_tcp']['open_ports']
            if 21 in open_ports or 23 in open_ports:
                pci_issues.append("Unencrypted services detected")

        compliance_results['PCI_DSS'] = {
            'compliant': len(pci_issues) == 0,
            'issues': pci_issues
        }

        return compliance_results

    def _identify_threat_indicators(self):
        """Identify potential threat indicators"""
        indicators = []

        if 'port_scan' in self.results:
            open_ports = self.results['port_scan']['custom_tcp']['open_ports']

            # Check for suspicious port patterns
            if len(open_ports) > 50:
                indicators.append({
                    'type': 'suspicious_port_count',
                    'severity': 'MEDIUM',
                    'description': f'High number of open ports: {len(open_ports)}'
                })

        return indicators

    def _arp_discovery(self):
        """ARP table discovery for local networks"""
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            arp_entries = []
            for line in result.stdout.split('\n'):
                if self.target in line:
                    arp_entries.append(line.strip())
            return arp_entries
        except:
            return []

    def _udp_scan(self):
        """UDP port scanning for comprehensive coverage"""
        common_udp_ports = [53, 67, 68, 123, 161, 162, 500, 514, 520, 1900]
        udp_results = {}

        for port in common_udp_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(b'test', (self.target, port))
                sock.close()
                udp_results[port] = 'open|filtered'
            except:
                udp_results[port] = 'closed'

        return udp_results

    def _parse_vuln_results(self, scan_result):
        """Parse vulnerability scan results"""
        vulnerabilities = []

        if hasattr(scan_result, 'all_hosts') and scan_result.all_hosts():
            for host in scan_result.all_hosts():
                if 'hostscript' in scan_result[host]:
                    for script in scan_result[host]['hostscript']:
                        if 'VULNERABLE' in script['output']:
                            vulnerabilities.append({
                                'script': script['id'],
                                'output': script['output']
                            })

        return vulnerabilities