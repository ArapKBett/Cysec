#!/usr/bin/env python3
"""
Blue Team Remediation Engine - Real Security Hardening
Actual vulnerability remediation and system hardening tool

🛡️ SYSTEM HARDENING TOOL 🛡️
Provides real remediation commands and security configurations
"""

import os
import subprocess
import json
import yaml
from datetime import datetime
from pathlib import Path
import shutil

class RemediationEngine:
    def __init__(self, exploit_report=None):
        self.exploit_report = exploit_report
        self.remediation_dir = Path("blueteam_remediation")
        self.remediation_dir.mkdir(exist_ok=True)

        self.vulnerabilities = []
        self.fixes_applied = []

        if exploit_report and Path(exploit_report).exists():
            self.load_exploit_report(exploit_report)

        # Real remediation commands and configurations
        self.remediation_playbook = {
            "SMTP_OPEN_RELAY": {
                "severity": "CRITICAL",
                "description": "SMTP server configured as open relay",
                "immediate_actions": [
                    "Stop SMTP service immediately",
                    "Review and fix relay configuration",
                    "Enable authentication requirements"
                ],
                "fixes": {
                    "postfix": {
                        "config_file": "/etc/postfix/main.cf",
                        "settings": {
                            "smtpd_recipient_restrictions": "permit_mynetworks,reject_unauth_destination",
                            "smtpd_relay_restrictions": "permit_mynetworks,reject_unauth_destination",
                            "smtpd_client_restrictions": "permit_mynetworks,reject_unknown_client_hostname",
                            "disable_vrfy_command": "yes",
                            "smtpd_helo_required": "yes"
                        },
                        "commands": [
                            "sudo systemctl stop postfix",
                            "sudo cp /etc/postfix/main.cf /etc/postfix/main.cf.backup",
                            "sudo postconf -e 'smtpd_recipient_restrictions = permit_mynetworks,reject_unauth_destination'",
                            "sudo postconf -e 'smtpd_relay_restrictions = permit_mynetworks,reject_unauth_destination'",
                            "sudo postconf -e 'disable_vrfy_command = yes'",
                            "sudo postfix check",
                            "sudo systemctl start postfix"
                        ]
                    }
                }
            },
            "SSH_WEAK_CREDENTIALS": {
                "severity": "CRITICAL",
                "description": "SSH accessible with weak credentials",
                "immediate_actions": [
                    "Disable password authentication",
                    "Force key-based authentication only",
                    "Change default passwords immediately"
                ],
                "fixes": {
                    "ssh_config": {
                        "config_file": "/etc/ssh/sshd_config",
                        "settings": {
                            "PasswordAuthentication": "no",
                            "PubkeyAuthentication": "yes",
                            "PermitRootLogin": "no",
                            "MaxAuthTries": "3",
                            "LoginGraceTime": "30",
                            "AllowUsers": "specify_allowed_users"
                        },
                        "commands": [
                            "sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup",
                            "sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config",
                            "sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config",
                            "sudo sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config",
                            "sudo sshd -t",
                            "sudo systemctl restart sshd"
                        ]
                    }
                }
            },
            "RDP_EXPOSED": {
                "severity": "HIGH",
                "description": "RDP service exposed to network",
                "immediate_actions": [
                    "Disable RDP service if not essential",
                    "Change RDP port from default 3389",
                    "Enable Network Level Authentication"
                ],
                "fixes": {
                    "linux_rdp": {
                        "commands": [
                            "sudo systemctl stop xrdp",
                            "sudo systemctl disable xrdp",
                            "sudo ufw deny 3389/tcp"
                        ]
                    },
                    "windows_rdp": {
                        "registry_changes": [
                            "reg add 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' /v PortNumber /t REG_DWORD /d 33389",
                            "reg add 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' /v UserAuthentication /t REG_DWORD /d 1"
                        ],
                        "firewall": [
                            "netsh advfirewall firewall delete rule name='Remote Desktop'",
                            "netsh advfirewall firewall add rule name='Remote Desktop Custom' dir=in action=allow protocol=TCP localport=33389"
                        ]
                    }
                }
            },
            "MISSING_SECURITY_HEADERS": {
                "severity": "MEDIUM",
                "description": "Web server missing security headers",
                "immediate_actions": [
                    "Configure security headers",
                    "Enable HTTPS enforcement",
                    "Implement Content Security Policy"
                ],
                "fixes": {
                    "nginx": {
                        "config_file": "/etc/nginx/nginx.conf",
                        "headers": """
# Security Headers
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
                        """,
                        "commands": [
                            "sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup",
                            "sudo nginx -t",
                            "sudo systemctl reload nginx"
                        ]
                    },
                    "apache": {
                        "config_file": "/etc/apache2/apache2.conf",
                        "headers": """
# Security Headers
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set Content-Security-Policy "default-src 'self'"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
                        """,
                        "commands": [
                            "sudo a2enmod headers",
                            "sudo apache2ctl configtest",
                            "sudo systemctl reload apache2"
                        ]
                    }
                }
            },
            "SQL_INJECTION": {
                "severity": "CRITICAL",
                "description": "Web application vulnerable to SQL injection",
                "immediate_actions": [
                    "Take application offline immediately",
                    "Review and patch vulnerable code",
                    "Implement input validation and parameterized queries"
                ],
                "fixes": {
                    "application_firewall": {
                        "modsecurity": [
                            "sudo apt-get install libapache2-mod-security2",
                            "sudo a2enmod security2",
                            "sudo wget -O /etc/modsecurity/crs-setup.conf https://raw.githubusercontent.com/coreruleset/coreruleset/v3.3/dev/crs-setup.conf.example",
                            "sudo systemctl restart apache2"
                        ]
                    },
                    "database_hardening": [
                        "sudo mysql -e \"DELETE FROM mysql.user WHERE User='';\"",
                        "sudo mysql -e \"DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');\"",
                        "sudo mysql -e \"FLUSH PRIVILEGES;\""
                    ]
                }
            },
            "ADMIN_INTERFACE_EXPOSED": {
                "severity": "MEDIUM",
                "description": "Administrative interface accessible without protection",
                "immediate_actions": [
                    "Restrict access to admin interfaces",
                    "Implement IP whitelisting",
                    "Add authentication protection"
                ],
                "fixes": {
                    "nginx_protection": {
                        "config": """
location /admin {
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    deny all;
    auth_basic "Restricted Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
                        """,
                        "commands": [
                            "sudo htpasswd -c /etc/nginx/.htpasswd admin",
                            "sudo nginx -t",
                            "sudo systemctl reload nginx"
                        ]
                    }
                }
            }
        }

    def load_exploit_report(self, report_file):
        """Load vulnerabilities from exploit report"""
        try:
            with open(report_file, 'r') as f:
                report_data = json.load(f)

            self.vulnerabilities = report_data.get("vulnerabilities", [])
            print(f"[*] Loaded {len(self.vulnerabilities)} vulnerabilities from report")

        except Exception as e:
            print(f"[!] Error loading exploit report: {e}")

    def create_remediation_script(self, vulnerability, target):
        """Create remediation script for specific vulnerability"""
        vuln_type = vulnerability.get("vulnerability", "")

        if vuln_type not in self.remediation_playbook:
            return None

        playbook = self.remediation_playbook[vuln_type]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        script_file = self.remediation_dir / f"fix_{vuln_type.lower()}_{timestamp}.sh"

        script_content = f"""#!/bin/bash
# Automated Remediation Script
# Vulnerability: {vuln_type}
# Target: {target}
# Generated: {datetime.now()}
# Severity: {playbook['severity']}

set -e  # Exit on error
set -u  # Exit on undefined variable

echo "=========================================="
echo "VULNERABILITY REMEDIATION SCRIPT"
echo "=========================================="
echo "Vulnerability: {vuln_type}"
echo "Target: {target}"
echo "Severity: {playbook['severity']}"
echo "Time: $(date)"
echo ""

echo "Description: {playbook['description']}"
echo ""

echo "Immediate Actions Required:"
"""

        for i, action in enumerate(playbook["immediate_actions"], 1):
            script_content += f'echo "  {i}. {action}"\n'

        script_content += '\necho ""\necho "Starting automated remediation..."\necho ""\n\n'

        # Add fix commands based on vulnerability type
        fixes = playbook.get("fixes", {})

        for fix_name, fix_config in fixes.items():
            script_content += f'echo "Applying {fix_name} fixes..."\n\n'

            # Backup existing configurations
            if "config_file" in fix_config:
                config_file = fix_config["config_file"]
                script_content += f'# Backup original configuration\nif [ -f "{config_file}" ]; then\n'
                script_content += f'    sudo cp "{config_file}" "{config_file}.backup.$(date +%Y%m%d_%H%M%S)"\n'
                script_content += f'    echo "Backup created: {config_file}.backup.$(date +%Y%m%d_%H%M%S)"\nfi\n\n'

            # Add configuration commands
            if "commands" in fix_config:
                script_content += "# Execute remediation commands\n"
                for cmd in fix_config["commands"]:
                    script_content += f'echo "Executing: {cmd}"\n'
                    script_content += f'{cmd}\n'
                    script_content += 'if [ $? -eq 0 ]; then\n'
                    script_content += '    echo "✓ Command successful"\nelse\n'
                    script_content += '    echo "✗ Command failed"\n    exit 1\nfi\n\n'

        script_content += '''
echo "=========================================="
echo "REMEDIATION COMPLETED SUCCESSFULLY"
echo "=========================================="
echo "Please verify the fixes:"
echo "1. Test service functionality"
echo "2. Check security configuration"
echo "3. Monitor for any issues"
echo "4. Update documentation"
echo ""
echo "Remediation completed at: $(date)"
'''

        # Write script
        with open(script_file, 'w') as f:
            f.write(script_content)

        os.chmod(script_file, 0o755)
        return script_file

    def create_system_hardening_script(self):
        """Create comprehensive system hardening script"""
        hardening_script = self.remediation_dir / "system_hardening.sh"

        script_content = """#!/bin/bash
# Comprehensive System Hardening Script
# Generated by Blue Team Remediation Engine

set -e

echo "============================================"
echo "SYSTEM HARDENING SCRIPT"
echo "============================================"
echo "Starting system hardening at: $(date)"
echo ""

# Update system
echo "[1/10] Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Configure firewall
echo "[2/10] Configuring firewall..."
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw --force enable

# Secure SSH configuration
echo "[3/10] Hardening SSH configuration..."
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)

# SSH hardening settings
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sudo sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
sudo sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 2/' /etc/ssh/sshd_config

# Test SSH configuration
sudo sshd -t
sudo systemctl restart sshd

# Configure fail2ban
echo "[4/10] Installing and configuring fail2ban..."
sudo apt install fail2ban -y

sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
EOF

sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Disable unnecessary services
echo "[5/10] Disabling unnecessary services..."
services_to_disable=(
    "telnet"
    "rsh"
    "rlogin"
    "finger"
    "talk"
    "ntalk"
)

for service in "${services_to_disable[@]}"; do
    if systemctl is-enabled $service 2>/dev/null; then
        sudo systemctl disable $service
        sudo systemctl stop $service
        echo "Disabled: $service"
    fi
done

# Secure kernel parameters
echo "[6/10] Configuring kernel security parameters..."
sudo tee /etc/sysctl.d/99-security.conf > /dev/null <<EOF
# IP Spoofing protection
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 1

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
EOF

sudo sysctl -p /etc/sysctl.d/99-security.conf

# Set up log monitoring
echo "[7/10] Configuring log monitoring..."
sudo apt install logwatch -y

# Configure automatic security updates
echo "[8/10] Enabling automatic security updates..."
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades

# Install and configure antivirus
echo "[9/10] Installing ClamAV antivirus..."
sudo apt install clamav clamav-daemon -y
sudo freshclam
sudo systemctl enable clamav-daemon

# File permission hardening
echo "[10/10] Hardening file permissions..."
sudo chmod 700 /root
sudo chmod 644 /etc/passwd
sudo chmod 600 /etc/shadow
sudo chmod 644 /etc/group

echo "============================================"
echo "SYSTEM HARDENING COMPLETED"
echo "============================================"
echo "Summary:"
echo "✓ System packages updated"
echo "✓ Firewall configured and enabled"
echo "✓ SSH hardened"
echo "✓ Fail2ban installed and configured"
echo "✓ Unnecessary services disabled"
echo "✓ Kernel security parameters set"
echo "✓ Log monitoring configured"
echo "✓ Automatic updates enabled"
echo "✓ Antivirus installed"
echo "✓ File permissions hardened"
echo ""
echo "Please reboot the system to ensure all changes take effect."
echo "Hardening completed at: $(date)"
"""

        with open(hardening_script, 'w') as f:
            f.write(script_content)

        os.chmod(hardening_script, 0o755)
        return hardening_script

    def create_monitoring_configuration(self):
        """Create security monitoring configuration"""

        # Create Suricata rules for detected threats
        suricata_rules = self.remediation_dir / "custom_suricata.rules"

        rules_content = """# Custom Suricata Rules for Detected Vulnerabilities
# Generated by Blue Team Remediation Engine

# Detect SSH brute force attempts
alert tcp any any -> any 22 (msg:"SSH Brute Force Attempt"; flow:to_server; content:"SSH-"; detection_filter:track by_src, count 5, seconds 60; sid:1000001; rev:1;)

# Detect RDP brute force attempts
alert tcp any any -> any 3389 (msg:"RDP Brute Force Attempt"; flow:to_server; detection_filter:track by_src, count 3, seconds 60; sid:1000002; rev:1;)

# Detect SMTP relay attempts
alert tcp any any -> any 25 (msg:"SMTP Relay Attempt"; flow:to_server; content:"MAIL FROM:"; content:"RCPT TO:"; distance:0; sid:1000003; rev:1;)

# Detect SQL injection attempts
alert http any any -> any any (msg:"SQL Injection Attempt"; content:"' OR '1'='1"; sid:1000004; rev:1;)
alert http any any -> any any (msg:"SQL Injection Attempt - Union"; content:"UNION SELECT"; nocase; sid:1000005; rev:1;)

# Detect XSS attempts
alert http any any -> any any (msg:"XSS Attempt"; content:"<script>"; nocase; sid:1000006; rev:1;)

# Detect directory traversal
alert http any any -> any any (msg:"Directory Traversal Attempt"; content:"../"; sid:1000007; rev:1;)
"""

        with open(suricata_rules, 'w') as f:
            f.write(rules_content)

        # Create OSSEC configuration
        ossec_config = self.remediation_dir / "ossec_local_rules.xml"

        ossec_content = """<!-- Custom OSSEC Rules -->
<group name="vulnerability_monitoring">

  <!-- SSH brute force detection -->
  <rule id="100001" level="10">
    <if_matched_sid>5716</if_matched_sid>
    <description>SSH brute force attack detected</description>
    <group>authentication_failures,</group>
  </rule>

  <!-- Web application attacks -->
  <rule id="100002" level="12">
    <decoded_as>web-accesslog</decoded_as>
    <regex>sql|union|select|drop|insert|update|delete</regex>
    <description>SQL injection attempt detected</description>
    <group>web,attack,</group>
  </rule>

  <!-- Administrative interface access -->
  <rule id="100003" level="8">
    <decoded_as>web-accesslog</decoded_as>
    <url>/admin|/administrator|/wp-admin</url>
    <description>Administrative interface access attempt</description>
    <group>web,</group>
  </rule>

</group>"""

        with open(ossec_config, 'w') as f:
            f.write(ossec_content)

        return suricata_rules, ossec_config

    def generate_remediation_report(self):
        """Generate comprehensive remediation report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.remediation_dir / f"remediation_report_{timestamp}.json"

        # Analyze vulnerabilities by severity
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        vulnerability_types = {}

        for vuln in self.vulnerabilities:
            if vuln.get("status") == "VULNERABLE":
                vuln_type = vuln.get("vulnerability", "UNKNOWN")
                severity = "MEDIUM"  # Default

                if vuln_type in self.remediation_playbook:
                    severity = self.remediation_playbook[vuln_type]["severity"]

                severity_count[severity] += 1

                if vuln_type not in vulnerability_types:
                    vulnerability_types[vuln_type] = 0
                vulnerability_types[vuln_type] += 1

        report_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tool": "Blue Team Remediation Engine",
                "vulnerabilities_analyzed": len(self.vulnerabilities)
            },
            "summary": {
                "severity_breakdown": severity_count,
                "vulnerability_types": vulnerability_types,
                "remediation_scripts_generated": len(self.fixes_applied)
            },
            "vulnerabilities": self.vulnerabilities,
            "remediation_actions": self.fixes_applied,
            "next_steps": [
                "Execute critical remediation scripts immediately",
                "Verify all fixes are properly applied",
                "Test system functionality after remediation",
                "Implement continuous monitoring",
                "Schedule regular security assessments",
                "Update incident response procedures"
            ]
        }

        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)

        return report_file

    def run_remediation_engine(self):
        """Run complete remediation engine"""
        print("🛡️ BLUE TEAM REMEDIATION ENGINE")
        print("=" * 40)
        print("Analyzing vulnerabilities and generating fixes...")

        remediation_scripts = []

        # Process each vulnerability
        for vuln in self.vulnerabilities:
            if vuln.get("status") == "VULNERABLE":
                target = vuln.get("target")
                vuln_type = vuln.get("vulnerability")

                if vuln_type in self.remediation_playbook:
                    print(f"\n[*] Creating remediation for {vuln_type} on {target}")

                    script = self.create_remediation_script(vuln, target)
                    if script:
                        remediation_scripts.append(script)
                        self.fixes_applied.append({
                            "vulnerability": vuln_type,
                            "target": target,
                            "script": str(script),
                            "timestamp": datetime.now().isoformat()
                        })

        # Create system hardening script
        print("\n[*] Creating system hardening script...")
        hardening_script = self.create_system_hardening_script()

        # Create monitoring configuration
        print("[*] Creating monitoring configuration...")
        suricata_rules, ossec_config = self.create_monitoring_configuration()

        # Generate report
        print("[*] Generating remediation report...")
        report = self.generate_remediation_report()

        print(f"\n✅ REMEDIATION ENGINE COMPLETE")
        print(f"📁 Output directory: {self.remediation_dir}/")
        print(f"🛠️ Remediation scripts: {len(remediation_scripts)}")
        print(f"🔧 System hardening: {hardening_script}")
        print(f"👁️ Monitoring rules: {suricata_rules}, {ossec_config}")
        print(f"📊 Report: {report}")

        return {
            "remediation_scripts": remediation_scripts,
            "hardening_script": hardening_script,
            "monitoring_config": [suricata_rules, ossec_config],
            "report": report
        }

def main():
    """Main remediation function"""
    # Look for exploit report
    exploit_reports = list(Path(".").glob("exploit_evidence/redteam_exploit_report_*.json"))

    if exploit_reports:
        latest_report = max(exploit_reports, key=os.path.getctime)
        print(f"[*] Found exploit report: {latest_report}")

        engine = RemediationEngine(latest_report)
        results = engine.run_remediation_engine()

        return results
    else:
        print("[!] No exploit report found. Run redteam_exploit_engine.py first")
        return None

if __name__ == "__main__":
    main()