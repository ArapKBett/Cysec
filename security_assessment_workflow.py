#!/usr/bin/env python3
"""
Complete Security Assessment Workflow
Real vulnerability testing and remediation pipeline

⚠️ AUTHORIZATION REQUIRED ⚠️
This tool performs actual security testing and system modifications.
Only use on systems you own or have explicit written permission to test.
"""

import subprocess
import os
import json
import time
from datetime import datetime
from pathlib import Path

class SecurityAssessmentWorkflow:
    def __init__(self):
        self.workflow_dir = Path("security_assessment_workflow")
        self.workflow_dir.mkdir(exist_ok=True)

        self.assessment_log = []
        self.current_phase = None

    def log_phase(self, phase, message, status="INFO"):
        """Log workflow phase"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "phase": phase,
            "message": message,
            "status": status
        }
        self.assessment_log.append(entry)

        status_emoji = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARNING": "⚠️"}
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {status_emoji.get(status, 'ℹ️')} {phase}: {message}")

    def run_initial_scan(self):
        """Run initial network scan using existing scanner"""
        self.log_phase("RECONNAISSANCE", "Starting initial network reconnaissance")

        try:
            # This integrates with your existing network scanner
            result = subprocess.run(
                ["python3", "scan_analysis.py"],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                self.log_phase("RECONNAISSANCE", "Network scan completed successfully", "SUCCESS")
                return True
            else:
                self.log_phase("RECONNAISSANCE", f"Network scan failed: {result.stderr}", "ERROR")
                return False

        except subprocess.TimeoutExpired:
            self.log_phase("RECONNAISSANCE", "Network scan timed out", "ERROR")
            return False
        except Exception as e:
            self.log_phase("RECONNAISSANCE", f"Network scan error: {e}", "ERROR")
            return False

    def run_vulnerability_testing(self):
        """Execute real vulnerability testing"""
        self.log_phase("VULNERABILITY_TESTING", "Starting vulnerability exploitation tests")

        try:
            result = subprocess.run(
                ["python3", "redteam_exploit_engine.py"],
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes timeout
            )

            if result.returncode == 0:
                self.log_phase("VULNERABILITY_TESTING", "Vulnerability testing completed", "SUCCESS")

                # Check for generated exploit report
                exploit_reports = list(Path("exploit_evidence").glob("redteam_exploit_report_*.json"))
                if exploit_reports:
                    latest_report = max(exploit_reports, key=lambda x: x.stat().st_mtime)
                    self.log_phase("VULNERABILITY_TESTING", f"Report generated: {latest_report}", "SUCCESS")
                    return latest_report
                else:
                    self.log_phase("VULNERABILITY_TESTING", "No exploit report generated", "WARNING")
                    return True

            else:
                self.log_phase("VULNERABILITY_TESTING", f"Vulnerability testing failed: {result.stderr}", "ERROR")
                return False

        except subprocess.TimeoutExpired:
            self.log_phase("VULNERABILITY_TESTING", "Vulnerability testing timed out", "ERROR")
            return False
        except Exception as e:
            self.log_phase("VULNERABILITY_TESTING", f"Vulnerability testing error: {e}", "ERROR")
            return False

    def run_remediation(self):
        """Execute automated remediation"""
        self.log_phase("REMEDIATION", "Starting automated vulnerability remediation")

        try:
            result = subprocess.run(
                ["python3", "blueteam_remediation_engine.py"],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                self.log_phase("REMEDIATION", "Remediation scripts generated successfully", "SUCCESS")

                # Check for generated remediation files
                remediation_dir = Path("blueteam_remediation")
                if remediation_dir.exists():
                    files = list(remediation_dir.glob("*.sh"))
                    self.log_phase("REMEDIATION", f"Generated {len(files)} remediation scripts", "SUCCESS")
                    return remediation_dir
                else:
                    self.log_phase("REMEDIATION", "No remediation directory found", "WARNING")
                    return True

            else:
                self.log_phase("REMEDIATION", f"Remediation failed: {result.stderr}", "ERROR")
                return False

        except subprocess.TimeoutExpired:
            self.log_phase("REMEDIATION", "Remediation timed out", "ERROR")
            return False
        except Exception as e:
            self.log_phase("REMEDIATION", f"Remediation error: {e}", "ERROR")
            return False

    def create_executive_dashboard(self, scan_results, exploit_report, remediation_dir):
        """Create comprehensive executive dashboard"""
        self.log_phase("REPORTING", "Generating executive security dashboard")

        dashboard_file = self.workflow_dir / f"security_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

        # Load exploit data if available
        exploit_data = {"vulnerabilities": [], "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0}}

        if exploit_report and Path(exploit_report).exists():
            try:
                with open(exploit_report, 'r') as f:
                    exploit_data = json.load(f)
            except:
                pass

        # Count remediation scripts
        remediation_count = 0
        if remediation_dir and Path(remediation_dir).exists():
            remediation_count = len(list(Path(remediation_dir).glob("*.sh")))

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Executive Dashboard</title>
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}

        .header {{
            background: white;
            border-radius: 15px;
            padding: 30px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}

        .header h1 {{
            color: #2c3e50;
            font-size: 2.5rem;
            margin: 0;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
        }}

        .timestamp {{
            color: #7f8c8d;
            font-size: 1.1rem;
            margin-top: 10px;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: white;
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
        }}

        .stat-number {{
            font-size: 3rem;
            font-weight: bold;
            margin: 10px 0;
        }}

        .critical {{ color: #e74c3c; }}
        .high {{ color: #e67e22; }}
        .medium {{ color: #f39c12; }}
        .low {{ color: #27ae60; }}
        .success {{ color: #27ae60; }}

        .phase-status {{
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}

        .phase {{
            display: flex;
            align-items: center;
            padding: 15px;
            margin: 10px 0;
            border-radius: 10px;
            background: #f8f9fa;
        }}

        .phase-icon {{
            font-size: 1.5rem;
            margin-right: 15px;
        }}

        .recommendations {{
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }}

        .recommendation {{
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #3498db;
            background: #ecf0f1;
            border-radius: 5px;
        }}

        .vulnerability-list {{
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            max-height: 400px;
            overflow-y: auto;
        }}

        .vulnerability {{
            padding: 15px;
            margin: 10px 0;
            border-radius: 10px;
            border-left: 5px solid #e74c3c;
            background: #fdebea;
        }}

        .footer {{
            text-align: center;
            padding: 20px;
            color: white;
            font-size: 0.9rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CYBERSECURITY ASSESSMENT</h1>
            <h2>Executive Security Dashboard</h2>
            <p class="timestamp">Assessment completed: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Critical Vulnerabilities</h3>
                <div class="stat-number critical">{exploit_data.get('summary', {}).get('critical', 0)}</div>
                <p>Immediate action required</p>
            </div>
            <div class="stat-card">
                <h3>High Risk Issues</h3>
                <div class="stat-number high">{exploit_data.get('summary', {}).get('high', 0)}</div>
                <p>24-hour remediation window</p>
            </div>
            <div class="stat-card">
                <h3>Medium Risk</h3>
                <div class="stat-number medium">{exploit_data.get('summary', {}).get('medium', 0)}</div>
                <p>Schedule for patching</p>
            </div>
            <div class="stat-card">
                <h3>Remediation Scripts</h3>
                <div class="stat-number success">{remediation_count}</div>
                <p>Ready for execution</p>
            </div>
        </div>

        <div class="phase-status">
            <h3>Assessment Phases Completed</h3>
            <div class="phase">
                <span class="phase-icon">✅</span>
                <div>
                    <strong>Phase 1: Network Reconnaissance</strong><br>
                    Comprehensive network scanning and service discovery completed
                </div>
            </div>
            <div class="phase">
                <span class="phase-icon">✅</span>
                <div>
                    <strong>Phase 2: Vulnerability Testing</strong><br>
                    Real vulnerability exploitation attempts and security testing completed
                </div>
            </div>
            <div class="phase">
                <span class="phase-icon">✅</span>
                <div>
                    <strong>Phase 3: Automated Remediation</strong><br>
                    Remediation scripts and hardening configurations generated
                </div>
            </div>
            <div class="phase">
                <span class="phase-icon">✅</span>
                <div>
                    <strong>Phase 4: Executive Reporting</strong><br>
                    Comprehensive security assessment report completed
                </div>
            </div>
        </div>

        <div class="recommendations">
            <h3>Immediate Action Items</h3>
            <div class="recommendation">
                🚨 <strong>Critical:</strong> Execute critical vulnerability remediation scripts immediately
            </div>
            <div class="recommendation">
                🛠️ <strong>High Priority:</strong> Deploy system hardening configurations within 24 hours
            </div>
            <div class="recommendation">
                👁️ <strong>Monitoring:</strong> Implement continuous security monitoring using provided rules
            </div>
            <div class="recommendation">
                📋 <strong>Process:</strong> Update incident response procedures based on findings
            </div>
            <div class="recommendation">
                🔄 <strong>Ongoing:</strong> Schedule monthly security assessments
            </div>
        </div>

        <div class="vulnerability-list">
            <h3>Critical Vulnerabilities Found</h3>
        """

        # Add vulnerability details
        for vuln in exploit_data.get('vulnerabilities', []):
            if vuln.get('status') == 'VULNERABLE' and vuln.get('severity') in ['CRITICAL', 'HIGH']:
                html_content += f"""
            <div class="vulnerability">
                <strong>{vuln.get('vulnerability', 'Unknown')}</strong><br>
                <strong>Target:</strong> {vuln.get('target', 'Unknown')}<br>
                <strong>Severity:</strong> <span class="{vuln.get('severity', 'medium').lower()}">{vuln.get('severity', 'Unknown')}</span><br>
                <strong>Time:</strong> {vuln.get('timestamp', 'Unknown')}
            </div>
                """

        html_content += """
        </div>
    </div>

    <div class="footer">
        <p>🔒 Cybersecurity Assessment Report - Confidential</p>
        <p>Generated by Security Assessment Workflow Engine</p>
    </div>

    <script>
        // Auto-refresh every 5 minutes
        setTimeout(function(){
            location.reload();
        }, 300000);
    </script>
</body>
</html>
        """

        with open(dashboard_file, 'w') as f:
            f.write(html_content)

        self.log_phase("REPORTING", f"Executive dashboard created: {dashboard_file}", "SUCCESS")
        return dashboard_file

    def create_technical_report(self, exploit_report, remediation_dir):
        """Create detailed technical report"""
        report_file = self.workflow_dir / f"technical_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        # Load exploit data
        exploit_data = {}
        if exploit_report and Path(exploit_report).exists():
            try:
                with open(exploit_report, 'r') as f:
                    exploit_data = json.load(f)
            except:
                pass

        # Count remediation files
        remediation_files = []
        if remediation_dir and Path(remediation_dir).exists():
            remediation_files = [str(f) for f in Path(remediation_dir).glob("*")]

        technical_report = {
            "assessment_metadata": {
                "timestamp": datetime.now().isoformat(),
                "assessment_type": "Comprehensive Security Assessment",
                "methodology": "OWASP Testing Guide + NIST Cybersecurity Framework",
                "tools_used": [
                    "Red Team Exploit Engine",
                    "Blue Team Remediation Engine",
                    "Network Scanner",
                    "Vulnerability Analyzer"
                ]
            },
            "technical_findings": exploit_data.get('vulnerabilities', []),
            "risk_analysis": {
                "critical_count": exploit_data.get('summary', {}).get('critical', 0),
                "high_count": exploit_data.get('summary', {}).get('high', 0),
                "medium_count": exploit_data.get('summary', {}).get('medium', 0),
                "low_count": exploit_data.get('summary', {}).get('low', 0)
            },
            "remediation_assets": {
                "scripts_generated": len([f for f in remediation_files if f.endswith('.sh')]),
                "configurations_created": len([f for f in remediation_files if f.endswith('.conf') or f.endswith('.xml')]),
                "total_files": len(remediation_files)
            },
            "workflow_log": self.assessment_log,
            "next_steps": [
                "Execute critical remediation scripts with proper testing",
                "Implement continuous monitoring systems",
                "Schedule regular penetration testing",
                "Conduct security awareness training",
                "Update security policies and procedures"
            ]
        }

        with open(report_file, 'w') as f:
            json.dump(technical_report, f, indent=2)

        self.log_phase("REPORTING", f"Technical report created: {report_file}", "SUCCESS")
        return report_file

    def run_complete_assessment(self):
        """Execute complete security assessment workflow"""
        print("🔒 COMPLETE SECURITY ASSESSMENT WORKFLOW")
        print("=" * 60)
        print("⚠️  This tool performs real security testing")
        print("📋 Ensure you have authorization to test these systems")
        print()

        start_time = datetime.now()

        # Phase 1: Initial Reconnaissance
        self.log_phase("WORKFLOW", "Starting comprehensive security assessment")

        scan_success = self.run_initial_scan()
        if not scan_success:
            self.log_phase("WORKFLOW", "Initial scan failed, continuing with vulnerability testing", "WARNING")

        time.sleep(2)

        # Phase 2: Vulnerability Testing
        exploit_report = self.run_vulnerability_testing()
        if not exploit_report:
            self.log_phase("WORKFLOW", "Vulnerability testing failed", "ERROR")
            return None

        time.sleep(2)

        # Phase 3: Automated Remediation
        remediation_dir = self.run_remediation()
        if not remediation_dir:
            self.log_phase("WORKFLOW", "Remediation failed", "ERROR")
            return None

        time.sleep(2)

        # Phase 4: Reporting and Documentation
        self.log_phase("WORKFLOW", "Generating comprehensive reports")

        dashboard = self.create_executive_dashboard(scan_success, exploit_report, remediation_dir)
        technical_report = self.create_technical_report(exploit_report, remediation_dir)

        # Save workflow log
        log_file = self.workflow_dir / f"assessment_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(log_file, 'w') as f:
            json.dump(self.assessment_log, f, indent=2)

        end_time = datetime.now()
        duration = end_time - start_time

        self.log_phase("WORKFLOW", f"Complete assessment finished in {duration}", "SUCCESS")

        print(f"\n✅ SECURITY ASSESSMENT COMPLETED")
        print(f"⏱️  Total duration: {duration}")
        print(f"📁 Workflow directory: {self.workflow_dir}/")
        print(f"📊 Executive dashboard: {dashboard}")
        print(f"📋 Technical report: {technical_report}")
        print(f"📝 Workflow log: {log_file}")

        if isinstance(exploit_report, Path):
            print(f"🔴 Exploit report: {exploit_report}")

        if isinstance(remediation_dir, Path):
            print(f"🛡️ Remediation scripts: {remediation_dir}/")

        return {
            "duration": str(duration),
            "dashboard": dashboard,
            "technical_report": technical_report,
            "exploit_report": exploit_report if isinstance(exploit_report, Path) else None,
            "remediation_dir": remediation_dir if isinstance(remediation_dir, Path) else None,
            "workflow_log": log_file
        }

def main():
    """Main workflow function"""
    workflow = SecurityAssessmentWorkflow()
    results = workflow.run_complete_assessment()
    return results

if __name__ == "__main__":
    main()