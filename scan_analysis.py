#!/usr/bin/env python3
"""
Network Scan Results Analysis Tool
Analyzes scan results and provides detailed security assessment
"""

import json
from datetime import datetime
from collections import defaultdict

# Sample scan data from your results
scan_results = {
    "scan_time": "2026-05-25 15:21:47",
    "target": "kabarak.ac.ke",
    "hosts_discovered": 3,
    "total_ports": 7,
    "vulnerabilities": 0,
    "detailed_results": [
        {"host": "192.168.150.84", "port": 53, "service": "DNS", "version": "BIND 9.11.3", "status": "Filtered", "vuln": "-"},
        {"host": "192.168.105.21", "port": 22, "service": "SSH", "version": "OpenSSH 8.2", "status": "Closed", "vuln": "-"},
        {"host": "192.168.105.21", "port": 80, "service": "HTTP", "version": "Apache 2.4.41", "status": "Closed", "vuln": "-"},
        {"host": "192.168.150.84", "port": 25, "service": "SMTP", "version": "Postfix", "status": "Open", "vuln": "CVE-2023-1234"},
        {"host": "192.168.105.21", "port": 53, "service": "DNS", "version": "BIND 9.11.3", "status": "Closed", "vuln": "-"},
        {"host": "192.168.105.21", "port": 22, "service": "SSH", "version": "OpenSSH 8.2", "status": "Open", "vuln": "-"},
        {"host": "192.168.105.21", "port": 443, "service": "HTTPS", "version": "nginx 1.18.0", "status": "Closed", "vuln": "CVE-2024-0001"},
        {"host": "192.168.150.84", "port": 443, "service": "HTTPS", "version": "nginx 1.18.0", "status": "Open", "vuln": "-"},
        {"host": "192.168.105.21", "port": 3389, "service": "RDP", "version": "Microsoft Terminal Services", "status": "Open", "vuln": "CVE-2023-5678"},
        {"host": "192.168.14.74", "port": 23, "service": "Telnet", "version": "Linux telnetd", "status": "Filtered", "vuln": "CVE-2024-0001"},
        {"host": "192.168.14.74", "port": 22, "service": "SSH", "version": "OpenSSH 8.2", "status": "Open", "vuln": "-"},
        {"host": "192.168.150.84", "port": 3389, "service": "RDP", "version": "Microsoft Terminal Services", "status": "Open", "vuln": "CVE-2024-0001"},
        {"host": "192.168.105.21", "port": 53, "service": "DNS", "version": "BIND 9.11.3", "status": "Filtered", "vuln": "CVE-2023-5678"},
        {"host": "192.168.105.21", "port": 22, "service": "SSH", "version": "OpenSSH 8.2", "status": "Closed", "vuln": "-"},
        {"host": "192.168.14.74", "port": 80, "service": "HTTP", "version": "Apache 2.4.41", "status": "Open", "vuln": "-"},
    ]
}

class ScanAnalyzer:
    def __init__(self, results):
        self.results = results
        self.hosts = defaultdict(list)
        self.vulnerabilities = []
        self.open_ports = []
        self.critical_services = []

        self._parse_results()

    def _parse_results(self):
        """Parse and categorize scan results"""
        for result in self.results["detailed_results"]:
            host = result["host"]
            self.hosts[host].append(result)

            if result["status"] == "Open":
                self.open_ports.append(result)

            if result["vuln"] != "-":
                self.vulnerabilities.append(result)

            # Identify critical services
            if result["service"] in ["RDP", "Telnet", "SSH"] and result["status"] == "Open":
                self.critical_services.append(result)

    def print_summary(self):
        """Print executive summary"""
        print("🛡️ CYBERSECURITY SCAN ANALYSIS REPORT")
        print("=" * 50)
        print(f"Target: {self.results['target']}")
        print(f"Scan Time: {self.results['scan_time']}")
        print(f"Hosts Discovered: {len(self.hosts)}")
        print(f"Open Ports: {len(self.open_ports)}")
        print(f"Potential Vulnerabilities: {len(self.vulnerabilities)}")
        print()

    def analyze_hosts(self):
        """Analyze each host individually"""
        print("🔍 HOST-BY-HOST ANALYSIS")
        print("=" * 30)

        for host, services in self.hosts.items():
            print(f"\n📡 Host: {host}")
            print("-" * 20)

            open_services = [s for s in services if s["status"] == "Open"]
            filtered_services = [s for s in services if s["status"] == "Filtered"]

            print(f"• Open Services: {len(open_services)}")
            print(f"• Filtered Services: {len(filtered_services)}")

            # Risk assessment
            risk_level = self._assess_host_risk(services)
            print(f"• Risk Level: {risk_level}")

            # Show open services
            if open_services:
                print("  Open Ports:")
                for service in open_services:
                    vuln_indicator = f" ⚠️ {service['vuln']}" if service['vuln'] != '-' else ""
                    print(f"    - {service['port']}/{service['service']} ({service['version']}){vuln_indicator}")

    def _assess_host_risk(self, services):
        """Assess risk level for a host"""
        open_count = len([s for s in services if s["status"] == "Open"])
        vuln_count = len([s for s in services if s["vuln"] != "-"])
        critical_services = [s for s in services if s["service"] in ["RDP", "Telnet"] and s["status"] == "Open"]

        if vuln_count > 2 or len(critical_services) > 0:
            return "🔴 HIGH"
        elif vuln_count > 0 or open_count > 3:
            return "🟡 MEDIUM"
        else:
            return "🟢 LOW"

    def analyze_vulnerabilities(self):
        """Analyze detected vulnerabilities"""
        print("\n⚠️ VULNERABILITY ANALYSIS")
        print("=" * 30)

        if not self.vulnerabilities:
            print("✅ No confirmed vulnerabilities detected")
            return

        vuln_by_cve = defaultdict(list)
        for vuln in self.vulnerabilities:
            vuln_by_cve[vuln["vuln"]].append(vuln)

        for cve, instances in vuln_by_cve.items():
            print(f"\n🚨 {cve}")
            print(f"   Affected hosts: {len(set(v['host'] for v in instances))}")
            print(f"   Services affected:")
            for instance in instances:
                print(f"     - {instance['host']}:{instance['port']} ({instance['service']})")

    def security_recommendations(self):
        """Provide security recommendations"""
        print("\n🛡️ SECURITY RECOMMENDATIONS")
        print("=" * 35)

        recommendations = []

        # Check for insecure services
        for service in self.open_ports:
            if service["service"] == "Telnet":
                recommendations.append("🔴 CRITICAL: Disable Telnet service - use SSH instead")
            elif service["service"] == "RDP" and service["port"] == 3389:
                recommendations.append("🟡 WARNING: RDP on default port - consider changing port or VPN access")
            elif service["service"] == "HTTP" and service["port"] == 80:
                recommendations.append("🟡 INFO: HTTP detected - ensure HTTPS is available")

        # Check for vulnerable versions
        for vuln in self.vulnerabilities:
            recommendations.append(f"🔴 PATCH REQUIRED: {vuln['host']}:{vuln['port']} affected by {vuln['vuln']}")

        if not recommendations:
            recommendations.append("✅ No immediate critical issues detected")

        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")

    def generate_next_steps(self):
        """Generate investigation next steps"""
        print("\n🔍 NEXT INVESTIGATION STEPS")
        print("=" * 30)

        steps = [
            "1. 📋 Verify scan results with targeted service scans",
            "2. 🔒 Check for default credentials on open services",
            "3. 🌐 Investigate web applications (if HTTP/HTTPS found)",
            "4. 📧 Test email services for security misconfigurations",
            "5. 🔑 Assess SSH key-based authentication",
            "6. 📱 Check for outdated software versions",
            "7. 🛡️ Validate firewall and access control effectiveness",
            "8. 📊 Document findings and create remediation plan"
        ]

        for step in steps:
            print(step)

    def export_results(self, filename=None):
        """Export detailed results"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_analysis_{timestamp}.json"

        analysis_data = {
            "scan_metadata": self.results,
            "analysis": {
                "total_hosts": len(self.hosts),
                "open_ports_count": len(self.open_ports),
                "vulnerabilities_count": len(self.vulnerabilities),
                "critical_services": self.critical_services,
                "host_analysis": dict(self.hosts)
            },
            "generated": datetime.now().isoformat()
        }

        with open(filename, 'w') as f:
            json.dump(analysis_data, f, indent=2)

        print(f"\n📁 Detailed analysis exported to: {filename}")

def main():
    """Main analysis function"""
    analyzer = ScanAnalyzer(scan_results)

    analyzer.print_summary()
    analyzer.analyze_hosts()
    analyzer.analyze_vulnerabilities()
    analyzer.security_recommendations()
    analyzer.generate_next_steps()
    analyzer.export_results()

if __name__ == "__main__":
    main()