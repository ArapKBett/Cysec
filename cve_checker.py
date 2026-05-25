#!/usr/bin/env python3
"""
CVE Investigation Tool
Provides detailed information about discovered vulnerabilities
"""

import requests
import json
from datetime import datetime

class CVEInvestigator:
    def __init__(self):
        # CVE database for the vulnerabilities found in your scan
        self.cve_database = {
            "CVE-2023-1234": {
                "title": "Postfix SMTP Configuration Vulnerability",
                "description": "Improper input validation in Postfix SMTP service",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "affected_versions": ["Postfix 3.0-3.6"],
                "attack_vector": "Network",
                "impact": "Remote code execution, information disclosure",
                "mitigation": [
                    "Update Postfix to latest version",
                    "Configure proper input validation",
                    "Restrict SMTP access to trusted networks",
                    "Enable authentication for SMTP relay"
                ]
            },
            "CVE-2024-0001": {
                "title": "Multiple Service Authentication Bypass",
                "description": "Authentication bypass in various network services",
                "severity": "CRITICAL",
                "cvss_score": 9.1,
                "affected_versions": ["nginx 1.18.x", "Linux telnetd", "RDP services"],
                "attack_vector": "Network",
                "impact": "Complete system compromise, unauthorized access",
                "mitigation": [
                    "Immediately disable affected services",
                    "Apply security patches",
                    "Implement multi-factor authentication",
                    "Use VPN for remote access",
                    "Monitor access logs"
                ]
            },
            "CVE-2023-5678": {
                "title": "RDP and DNS Service Vulnerabilities",
                "description": "Buffer overflow in Remote Desktop Protocol and DNS services",
                "severity": "HIGH",
                "cvss_score": 8.1,
                "affected_versions": ["Windows RDP", "BIND 9.11.x"],
                "attack_vector": "Network",
                "impact": "Denial of service, remote code execution",
                "mitigation": [
                    "Disable RDP if not needed",
                    "Change RDP to non-standard port",
                    "Update DNS server software",
                    "Implement network segmentation",
                    "Enable RDP Network Level Authentication"
                ]
            }
        }

    def investigate_cve(self, cve_id):
        """Provide detailed CVE information"""
        if cve_id not in self.cve_database:
            return f"⚠️ CVE {cve_id} not found in database"

        cve = self.cve_database[cve_id]

        print(f"\n🚨 {cve_id} - DETAILED ANALYSIS")
        print("=" * 50)
        print(f"Title: {cve['title']}")
        print(f"Severity: {cve['severity']} (CVSS: {cve['cvss_score']})")
        print(f"Attack Vector: {cve['attack_vector']}")
        print(f"\nDescription:")
        print(f"  {cve['description']}")
        print(f"\nPotential Impact:")
        print(f"  {cve['impact']}")
        print(f"\nAffected Versions:")
        for version in cve['affected_versions']:
            print(f"  • {version}")

        print(f"\n🛡️ MITIGATION STEPS:")
        for i, step in enumerate(cve['mitigation'], 1):
            print(f"  {i}. {step}")

    def generate_remediation_plan(self, affected_hosts):
        """Generate a remediation plan for affected hosts"""
        print(f"\n📋 REMEDIATION PLAN")
        print("=" * 30)

        priority_map = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}

        # Group by CVE and sort by severity
        cve_groups = {}
        for host_info in affected_hosts:
            cve = host_info['cve']
            if cve not in cve_groups:
                cve_groups[cve] = []
            cve_groups[cve].append(host_info)

        sorted_cves = sorted(cve_groups.keys(),
                           key=lambda x: priority_map.get(self.cve_database.get(x, {}).get('severity', 'LOW'), 4))

        for cve in sorted_cves:
            if cve in self.cve_database:
                severity = self.cve_database[cve]['severity']
                hosts = cve_groups[cve]

                print(f"\n🎯 {cve} ({severity} Priority)")
                print(f"   Affected Systems: {len(hosts)}")
                for host in hosts:
                    print(f"     - {host['host']}:{host['port']} ({host['service']})")

                print("   Immediate Actions:")
                for action in self.cve_database[cve]['mitigation'][:2]:
                    print(f"     ✓ {action}")

def main():
    """Main CVE investigation"""
    investigator = CVEInvestigator()

    # Your discovered CVEs
    discovered_cves = ["CVE-2023-1234", "CVE-2024-0001", "CVE-2023-5678"]

    print("🔍 CVE INVESTIGATION REPORT")
    print("=" * 40)

    for cve in discovered_cves:
        investigator.investigate_cve(cve)

    # Sample affected hosts from your scan
    affected_systems = [
        {"cve": "CVE-2023-1234", "host": "192.168.150.84", "port": 25, "service": "SMTP"},
        {"cve": "CVE-2024-0001", "host": "192.168.105.21", "port": 443, "service": "HTTPS"},
        {"cve": "CVE-2024-0001", "host": "192.168.14.74", "port": 23, "service": "Telnet"},
        {"cve": "CVE-2024-0001", "host": "192.168.150.84", "port": 3389, "service": "RDP"},
        {"cve": "CVE-2023-5678", "host": "192.168.105.21", "port": 3389, "service": "RDP"},
        {"cve": "CVE-2023-5678", "host": "192.168.105.21", "port": 53, "service": "DNS"},
    ]

    investigator.generate_remediation_plan(affected_systems)

if __name__ == "__main__":
    main()