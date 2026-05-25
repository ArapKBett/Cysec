#!/usr/bin/env python3
"""
Service Investigation Tool
Provides specific investigation steps for discovered services
"""

class ServiceInvestigator:
    def __init__(self):
        self.service_guides = {
            "SSH": {
                "default_checks": [
                    "Test for default credentials (admin:admin, root:root, etc.)",
                    "Check SSH version for known vulnerabilities",
                    "Attempt key-based authentication",
                    "Test for weak encryption algorithms",
                    "Check for SSH banner information disclosure"
                ],
                "tools": [
                    "ssh user@host",
                    "nmap -p 22 --script ssh-auth-methods <host>",
                    "ssh-audit <host>",
                    "hydra -L users.txt -P passwords.txt ssh://<host>"
                ]
            },
            "HTTP": {
                "default_checks": [
                    "Check for directory listing enabled",
                    "Test for common vulnerabilities (SQLi, XSS)",
                    "Identify web application technology",
                    "Check for admin panels (/admin, /wp-admin)",
                    "Test for file upload vulnerabilities"
                ],
                "tools": [
                    "curl -I http://<host>",
                    "nikto -h http://<host>",
                    "dirb http://<host>",
                    "sqlmap -u http://<host>"
                ]
            },
            "HTTPS": {
                "default_checks": [
                    "Test SSL/TLS configuration",
                    "Check certificate validity",
                    "Test for weak cipher suites",
                    "Check for HTTP Strict Transport Security",
                    "Verify certificate chain"
                ],
                "tools": [
                    "sslscan <host>:443",
                    "testssl.sh <host>",
                    "openssl s_client -connect <host>:443",
                    "nmap --script ssl-cert <host>"
                ]
            },
            "RDP": {
                "default_checks": [
                    "⚠️ HIGH RISK - Test for BlueKeep vulnerabilities",
                    "Check for default credentials",
                    "Test Network Level Authentication",
                    "Verify encryption settings",
                    "Check for session hijacking vulnerabilities"
                ],
                "tools": [
                    "nmap -p 3389 --script rdp-* <host>",
                    "rdesktop -u guest <host>",
                    "rdp-sec-check.pl <host>:3389"
                ]
            },
            "SMTP": {
                "default_checks": [
                    "Test for open relay configuration",
                    "Check for user enumeration (VRFY, EXPN)",
                    "Test authentication mechanisms",
                    "Check for information disclosure",
                    "Test for command injection vulnerabilities"
                ],
                "tools": [
                    "telnet <host> 25",
                    "smtp-user-enum -M VRFY -U users.txt -t <host>",
                    "nmap --script smtp-* <host>"
                ]
            },
            "DNS": {
                "default_checks": [
                    "Test for zone transfer (AXFR)",
                    "Check for DNS cache poisoning",
                    "Test recursive queries",
                    "Check for subdomain enumeration",
                    "Test for DNS amplification"
                ],
                "tools": [
                    "dig @<host> axfr <domain>",
                    "dnsrecon -t axfr -d <domain>",
                    "fierce -dns <domain>"
                ]
            },
            "Telnet": {
                "default_checks": [
                    "🔴 CRITICAL - Unencrypted protocol",
                    "Test default credentials",
                    "Check banner information",
                    "Test for privilege escalation",
                    "Immediate replacement with SSH recommended"
                ],
                "tools": [
                    "telnet <host>",
                    "nmap --script telnet-* <host>"
                ]
            }
        }

    def investigate_service(self, service_name, host, port):
        """Provide investigation guide for specific service"""
        print(f"\n🔍 INVESTIGATING {service_name} on {host}:{port}")
        print("=" * 50)

        if service_name not in self.service_guides:
            print(f"❌ No investigation guide available for {service_name}")
            return

        guide = self.service_guides[service_name]

        print("📋 RECOMMENDED CHECKS:")
        for i, check in enumerate(guide["default_checks"], 1):
            if check.startswith("🔴") or check.startswith("⚠️"):
                print(f"  {i}. {check}")
            else:
                print(f"  {i}. {check}")

        print(f"\n🛠️ INVESTIGATION COMMANDS:")
        for i, tool in enumerate(guide["tools"], 1):
            # Replace placeholder with actual host
            command = tool.replace("<host>", host).replace("<domain>", "kabarak.ac.ke")
            print(f"  {i}. {command}")

    def generate_investigation_script(self, open_services):
        """Generate automated investigation script"""
        print(f"\n🤖 AUTOMATED INVESTIGATION SCRIPT")
        print("=" * 40)

        print("#!/bin/bash")
        print("# Automated security investigation script")
        print("# Generated from scan results")
        print()

        for service in open_services:
            host = service['host']
            port = service['port']
            service_name = service['service']

            print(f"echo '--- Investigating {service_name} on {host}:{port} ---'")

            if service_name == "SSH":
                print(f"nmap -p {port} --script ssh-auth-methods {host}")
                print(f"ssh-audit {host}")

            elif service_name in ["HTTP", "HTTPS"]:
                scheme = "https" if service_name == "HTTPS" else "http"
                print(f"curl -I {scheme}://{host}:{port}")
                print(f"nikto -h {scheme}://{host}:{port}")

            elif service_name == "RDP":
                print(f"nmap -p {port} --script rdp-enum-encryption {host}")

            elif service_name == "SMTP":
                print(f"nmap -p {port} --script smtp-open-relay {host}")

            elif service_name == "DNS":
                print(f"dig @{host} version.bind chaos txt")

            elif service_name == "Telnet":
                print(f"echo 'CRITICAL: Telnet detected - immediate replacement recommended'")

            print()

def main():
    """Main service investigation"""
    investigator = ServiceInvestigator()

    # Your discovered open services
    open_services = [
        {"host": "192.168.150.84", "port": 25, "service": "SMTP"},
        {"host": "192.168.150.84", "port": 443, "service": "HTTPS"},
        {"host": "192.168.150.84", "port": 3389, "service": "RDP"},
        {"host": "192.168.105.21", "port": 22, "service": "SSH"},
        {"host": "192.168.105.21", "port": 3389, "service": "RDP"},
        {"host": "192.168.14.74", "port": 22, "service": "SSH"},
        {"host": "192.168.14.74", "port": 80, "service": "HTTP"}
    ]

    print("🔍 SERVICE INVESTIGATION GUIDE")
    print("=" * 40)

    # Investigate each service
    for service in open_services:
        investigator.investigate_service(
            service["service"],
            service["host"],
            service["port"]
        )

    # Generate automated script
    investigator.generate_investigation_script(open_services)

    print(f"\n📊 INVESTIGATION SUMMARY:")
    print(f"   Total services to investigate: {len(open_services)}")
    print(f"   Critical services found: {len([s for s in open_services if s['service'] in ['RDP', 'Telnet']])}")
    print(f"   Web services found: {len([s for s in open_services if s['service'] in ['HTTP', 'HTTPS']])}")

if __name__ == "__main__":
    main()