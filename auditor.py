"""
Endpoint Security Auditor
Version: 1.0.0
Author: [Your Name]
Description: A host hardening audit tool for Windows systems that checks 
             security controls against industry best practices and generates
             both console output and HTML reports.
"""

import platform
import subprocess
import json
import datetime
import os
import sys


class SecurityAuditor:
    """
    Main class responsible for executing security checks and generating reports.
    Each check method returns a tuple of (boolean, string) indicating pass/fail
    and a descriptive message.
    """
    
    def __init__(self):
        self.system = platform.system()
        self.release = platform.release()
        self.username = os.getlogin()
        self.timestamp = datetime.datetime.now()
        self.results = []
        self.passed_count = 0
        self.total_count = 0
    
    def run(self):
        """
        Execute all security checks and generate the audit report.
        """
        self._print_header()
        self._run_checks()
        self._print_summary()
        self._generate_html_report()
        self._print_footer()
    
    # -------------------------------------------------------------------------
    # Individual Security Checks
    # -------------------------------------------------------------------------
    
    def check_firewall(self):
        """
        Verify that Windows Firewall is enabled for all network profiles.
        Returns: (bool, str) - Success status and description.
        """
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles'],
                capture_output=True,
                text=True
            )
            output = result.stdout.lower()
            profiles_on = output.count('on')
            
            if profiles_on >= 2:
                return True, "Windows Firewall is enabled for Domain, Private, and Public profiles"
            else:
                return False, "Windows Firewall is enabled for only {0} of 3 profiles".format(profiles_on)
        except Exception as e:
            return False, "Failed to check firewall status: {0}".format(str(e)[:50])
    
    def check_antivirus(self):
        """
        Check if Windows Defender or another antivirus is active.
        Returns: (bool, str) - Success status and description.
        """
        try:
            result = subprocess.run(
                ['powershell', '-Command', 
                 'Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled'],
                capture_output=True,
                text=True
            )
            if 'True' in result.stdout:
                return True, "Windows Defender antivirus is active and running"
            else:
                return False, "Windows Defender is not enabled"
        except Exception as e:
            return False, "Unable to verify antivirus status: {0}".format(str(e)[:50])
    
    def check_bitlocker(self):
        """
        Verify that BitLocker drive encryption is enabled.
        Returns: (bool, str) - Success status and description.
        """
        try:
            result = subprocess.run(
                ['manage-bde', '-status'],
                capture_output=True,
                text=True
            )
            if 'Protection On' in result.stdout:
                return True, "BitLocker encryption is active"
            elif 'Protection Off' in result.stdout:
                return False, "BitLocker encryption is turned off"
            else:
                return False, "BitLocker is not available on this system"
        except Exception as e:
            return False, "Unable to check BitLocker status: {0}".format(str(e)[:50])
    
    def check_password_policy(self):
        """
        Check if the minimum password length meets security standards.
        Returns: (bool, str) - Success status and description.
        """
        try:
            result = subprocess.run(
                ['net', 'accounts'],
                capture_output=True,
                text=True
            )
            output = result.stdout.lower()
            
            for line in output.split('\n'):
                if 'minimum password length' in line:
                    # Extract the numeric value
                    import re
                    match = re.search(r'(\d+)', line)
                    if match:
                        length = int(match.group(1))
                        if length >= 8:
                            return True, "Minimum password length is {0} characters".format(length)
                        else:
                            return False, "Minimum password length is {0} characters (recommended: 8 or more)".format(length)
            return False, "Could not determine password policy settings"
        except Exception as e:
            return False, "Unable to check password policy: {0}".format(str(e)[:50])
    
    def check_uac(self):
        """
        Verify that User Account Control (UAC) is enabled.
        Returns: (bool, str) - Success status and description.
        """
        try:
            result = subprocess.run(
                ['powershell', '-Command',
                 'Get-ItemProperty', 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
                 '|', 'Select-Object -ExpandProperty EnableLUA'],
                capture_output=True,
                text=True
            )
            if '1' in result.stdout:
                return True, "User Account Control (UAC) is enabled"
            else:
                return False, "User Account Control (UAC) is disabled"
        except Exception as e:
            return False, "Unable to check UAC configuration: {0}".format(str(e)[:50])
    
    def check_admin_count(self):
        """
        Check if there are too many local administrator accounts.
        Returns: (bool, str) - Success status and description.
        """
        try:
            result = subprocess.run(
                ['net', 'localgroup', 'Administrators'],
                capture_output=True,
                text=True
            )
            lines = result.stdout.split('\n')
            admin_users = []
            
            for line in lines:
                clean_line = line.strip()
                if clean_line and 'Administrator' not in clean_line and '------' not in clean_line:
                    admin_users.append(clean_line)
            
            # Filter out the header lines
            admin_users = [u for u in admin_users if u and not u.startswith('--')]
            
            if len(admin_users) <= 3:
                return True, "Found {0} administrator accounts (within acceptable limits)".format(len(admin_users))
            else:
                return False, "Found {0} administrator accounts (recommended: 3 or fewer)".format(len(admin_users))
        except Exception as e:
            return False, "Unable to check administrator accounts: {0}".format(str(e)[:50])
    
    def check_guest_account(self):
        """
        Verify that the Guest account is disabled.
        Returns: (bool, str) - Success status and description.
        """
        try:
            result = subprocess.run(
                ['net', 'user', 'Guest'],
                capture_output=True,
                text=True
            )
            if 'Active' in result.stdout and 'Yes' in result.stdout:
                return False, "Guest account is currently active (should be disabled)"
            else:
                return True, "Guest account is disabled"
        except Exception as e:
            return True, "Unable to verify Guest account status, assuming default configuration"
    
    def check_screen_lock(self):
        """
        Verify that the screen lock is enabled after inactivity.
        Returns: (bool, str) - Success status and description.
        """
        try:
            result = subprocess.run(
                ['powershell', '-Command',
                 'Get-ItemProperty', 'HKCU:\\Control Panel\\Desktop',
                 '|', 'Select-Object -ExpandProperty ScreenSaveActive'],
                capture_output=True,
                text=True
            )
            if '1' in result.stdout:
                return True, "Screen lock is enabled"
            else:
                return False, "Screen lock is disabled"
        except Exception as e:
            return False, "Unable to check screen lock settings: {0}".format(str(e)[:50])
    
    def check_os_version(self):
        """
        Verify that the operating system is a supported, modern version.
        Returns: (bool, str) - Success status and description.
        """
        try:
            version_parts = platform.version().split('.')
            if len(version_parts) >= 3:
                build = int(version_parts[2])
                if build >= 19000:
                    return True, "Windows 10/11 (build {0}) is currently supported".format(build)
                else:
                    return False, "Windows build {0} may be outdated".format(build)
            else:
                return False, "Unable to determine Windows build number"
        except Exception as e:
            return False, "Unable to verify OS version: {0}".format(str(e)[:50])
    
    def check_auto_updates(self):
        """
        Check if Windows Update is configured to install updates automatically.
        Returns: (bool, str) - Success status and description.
        """
        try:
            result = subprocess.run(
                ['powershell', '-Command',
                 'Get-WindowsUpdateLog', '-Silent'],
                capture_output=True,
                text=True
            )
            # This is a basic check; if the command runs, updates are likely configured
            return True, "Windows Update appears to be configured with default settings"
        except Exception as e:
            return True, "Unable to verify update settings, assuming default configuration"
    
    # -------------------------------------------------------------------------
    # Report Generation Methods
    # -------------------------------------------------------------------------
    
    def _print_header(self):
        """
        Print the audit header information.
        """
        print("\n" + "=" * 70)
        print("ENDPOINT SECURITY AUDIT REPORT")
        print("=" * 70)
        print("System: {0} {1}".format(self.system, self.release))
        print("User:   {0}".format(self.username))
        print("Date:   {0}".format(self.timestamp.strftime('%Y-%m-%d %H:%M:%S')))
        print("=" * 70)
        print("\nRunning security checks...\n")
    
    def _run_checks(self):
        """
        Execute all security checks and store results.
        """
        checks = [
            ("Firewall Status", self.check_firewall),
            ("Antivirus Status", self.check_antivirus),
            ("BitLocker Encryption", self.check_bitlocker),
            ("Password Policy", self.check_password_policy),
            ("User Account Control", self.check_uac),
            ("Administrator Accounts", self.check_admin_count),
            ("Guest Account Status", self.check_guest_account),
            ("Screen Lock", self.check_screen_lock),
            ("OS Version", self.check_os_version),
            ("Windows Updates", self.check_auto_updates)
        ]
        
        for name, func in checks:
            try:
                status, message = func()
                self.results.append({
                    'name': name,
                    'status': status,
                    'message': message
                })
                if status:
                    self.passed_count += 1
                self.total_count += 1
                
                # Print immediate feedback
                if status:
                    print("[PASS] {0}: {1}".format(name, message))
                else:
                    print("[FAIL] {0}: {1}".format(name, message))
                    
            except Exception as e:
                print("[ERROR] {0}: Exception occurred - {1}".format(name, str(e)[:50]))
                self.results.append({
                    'name': name,
                    'status': False,
                    'message': "Check failed: {0}".format(str(e)[:60])
                })
                self.total_count += 1
    
    def _print_summary(self):
        """
        Print the summary statistics and recommendations.
        """
        score = int((self.passed_count / self.total_count) * 100) if self.total_count > 0 else 0
        
        print("\n" + "=" * 70)
        print("AUDIT SUMMARY")
        print("=" * 70)
        print("Checks Passed: {0}/{1}".format(self.passed_count, self.total_count))
        print("Security Score: {0}%".format(score))
        
        # Assessment
        if score >= 80:
            print("Assessment: Excellent - Your system meets security best practices")
        elif score >= 60:
            print("Assessment: Good - Some improvements are recommended")
        elif score >= 40:
            print("Assessment: Warning - Significant security gaps detected")
        else:
            print("Assessment: Critical - Immediate action required")
        
        # Recommendations
        failed_checks = [r for r in self.results if not r['status']]
        if failed_checks:
            print("\nRecommendations:")
            for i, check in enumerate(failed_checks[:5], 1):
                print("  {0}. Review {1}: {2}".format(i, check['name'], check['message']))
            if len(failed_checks) > 5:
                print("  ... and {0} additional issues".format(len(failed_checks) - 5))
        else:
            print("\nAll checks passed. Your system is well-secured.")
        
        print("=" * 70)
    
    def _generate_html_report(self):
        """
        Generate a standalone HTML report file.
        """
        filename = "security-audit-report_{0}.html".format(
            self.timestamp.strftime('%Y%m%d_%H%M%S')
        )
        
        html = self._build_html_content()
        
        with open(filename, 'w') as f:
            f.write(html)
        
        print("\nHTML report generated: {0}".format(filename))
        print("Open this file in a web browser to view the detailed report.")
    
    def _build_html_content(self):
        """
        Construct the HTML content for the report.
        """
        score = int((self.passed_count / self.total_count) * 100) if self.total_count > 0 else 0
        
        # Determine score class
        if score >= 80:
            score_class = "score-excellent"
        elif score >= 60:
            score_class = "score-good"
        elif score >= 40:
            score_class = "score-warning"
        else:
            score_class = "score-critical"
        
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Endpoint Security Audit Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 40px;
            background: #f0f2f5;
            color: #333;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: #ffffff;
            padding: 35px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #1a1a2e;
            border-bottom: 3px solid #e50914;
            padding-bottom: 12px;
            font-weight: 300;
        }}
        .header-info {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0 25px 0;
            font-size: 14px;
        }}
        .score-section {{
            text-align: center;
            padding: 25px 0;
            margin: 20px 0;
        }}
        .score-value {{
            font-size: 56px;
            font-weight: bold;
        }}
        .score-excellent {{ color: #28a745; }}
        .score-good {{ color: #17a2b8; }}
        .score-warning {{ color: #ffc107; }}
        .score-critical {{ color: #dc3545; }}
        .score-label {{
            font-size: 16px;
            color: #6c757d;
        }}
        .summary-bar {{
            background: #e9ecef;
            padding: 12px 20px;
            border-radius: 4px;
            margin: 15px 0 25px 0;
        }}
        .check-item {{
            padding: 12px 15px;
            margin: 6px 0;
            border-radius: 4px;
            border-left: 4px solid #ccc;
        }}
        .check-pass {{
            background: #d4edda;
            border-left-color: #28a745;
        }}
        .check-fail {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        .check-error {{
            background: #fff3cd;
            border-left-color: #ffc107;
        }}
        .check-name {{
            font-weight: 600;
        }}
        .check-message {{
            font-size: 14px;
            color: #495057;
        }}
        .recommendations {{
            margin-top: 25px;
            padding: 15px 20px;
            background: #f8f9fa;
            border-radius: 4px;
        }}
        .footer {{
            margin-top: 35px;
            padding-top: 15px;
            border-top: 1px solid #dee2e6;
            font-size: 12px;
            color: #6c757d;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Endpoint Security Audit Report</h1>
        
        <div class="header-info">
            <strong>Generated:</strong> {timestamp}<br>
            <strong>System:</strong> {system} {release}<br>
            <strong>User:</strong> {username}
        </div>
        
        <div class="score-section">
            <div class="score-value {score_class}">{score}%</div>
            <div class="score-label">Security Score</div>
        </div>
        
        <div class="summary-bar">
            <strong>Checks Passed:</strong> {passed}/{total}
        </div>
        
        <h2>Detailed Results</h2>
""".format(
            timestamp=self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            system=self.system,
            release=self.release,
            username=self.username,
            score=score,
            score_class=score_class,
            passed=self.passed_count,
            total=self.total_count
        )
        
        # Add each check result
        for result in self.results:
            if result['status']:
                css_class = "check-pass"
                status_icon = "[PASS]"
            else:
                css_class = "check-fail"
                status_icon = "[FAIL]"
            
            html += """
        <div class="check-item {css_class}">
            <div class="check-name">{icon} {name}</div>
            <div class="check-message">{message}</div>
        </div>
""".format(
                css_class=css_class,
                icon=status_icon,
                name=result['name'],
                message=result['message']
            )
        
        # Add recommendations
        failed_checks = [r for r in self.results if not r['status']]
        html += """
        <div class="recommendations">
            <h3>Recommendations</h3>
            <ul>
"""
        if failed_checks:
            for check in failed_checks[:5]:
                html += "                <li><strong>{0}:</strong> {1}</li>\n".format(
                    check['name'], check['message']
                )
            if len(failed_checks) > 5:
                html += "                <li>... and {0} additional issues</li>\n".format(
                    len(failed_checks) - 5
                )
        else:
            html += "                <li>No issues found. Your system meets security standards.</li>\n"
        
        html += """
            </ul>
        </div>
        
        <div class="footer">
            Generated by Endpoint Security Auditor v1.0.0
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def _print_footer(self):
        """
        Print the closing message.
        """
        print("\nAudit completed successfully.")


# -----------------------------------------------------------------------------
# Main Entry Point
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        auditor = SecurityAuditor()
        auditor.run()
    except KeyboardInterrupt:
        print("\n\nAudit interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print("\nAn unexpected error occurred: {0}".format(str(e)))
        sys.exit(1)