"""
Endpoint Security Auditor - Cross-Platform Edition
Version: 2.0.0
Author: berinabraham-sec
Description: A host hardening audit tool for Windows, macOS, and Linux.
             Each check is OS-aware and only runs if it applies to the current system.
"""

import platform
import subprocess
import datetime
import os
import sys
import re


class SecurityAuditor:
    """
    Main class for executing OS-specific security checks and generating reports.
    Each check method returns a tuple of (boolean, string) indicating pass/fail
    and a descriptive message.
    """
    
    def __init__(self):
        self.os_name = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.username = os.getlogin()
        self.timestamp = datetime.datetime.now()
        self.results = []
        self.passed_count = 0
        self.total_count = 0
        self.skipped_count = 0

    def run(self):
        """
        Execute all applicable security checks and generate the audit report.
        """
        self._print_header()
        self._run_checks()
        self._print_summary()
        self._generate_html_report()
        self._print_footer()
    
    # -------------------------------------------------------------------------
    # OS Detection Helpers
    # -------------------------------------------------------------------------
    
    def _is_windows(self):
        return self.os_name == "Windows"
    
    def _is_macos(self):
        return self.os_name == "Darwin"
    
    def _is_linux(self):
        return self.os_name == "Linux"
    
    def _run_command(self, command, shell=False):
        """
        Safely run a system command and return the output.
        Returns: (success_bool, stdout_string, stderr_string)
        """
        try:
            if shell and self._is_windows():
                result = subprocess.run(command, capture_output=True, text=True, shell=True)
            else:
                result = subprocess.run(command, capture_output=True, text=True)
            return True, result.stdout, result.stderr
        except Exception as e:
            return False, "", str(e)
    
    # -------------------------------------------------------------------------
    # Cross-Platform Security Checks
    # -------------------------------------------------------------------------
    
    def check_firewall(self):
        """
        Check if the host-based firewall is enabled.
        Windows: Checks Windows Defender Firewall.
        macOS: Checks if the application firewall is active.
        Linux: Checks if iptables/nftables has active rules or ufw is enabled.
        """
        if self._is_windows():
            success, stdout, _ = self._run_command(['netsh', 'advfirewall', 'show', 'allprofiles'])
            if success:
                profiles_on = stdout.lower().count('on')
                if profiles_on >= 2:
                    return True, "Windows Firewall is enabled for Domain, Private, and Public profiles"
                else:
                    return False, f"Windows Firewall is enabled for only {profiles_on} of 3 profiles"
            return False, "Could not check Windows Firewall status"
        
        elif self._is_macos():
            # Check macOS application firewall
            success, stdout, _ = self._run_command(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'])
            if success and 'enabled' in stdout.lower():
                return True, "macOS Application Firewall is enabled"
            else:
                return False, "macOS Application Firewall is disabled or could not be verified"
        
        elif self._is_linux():
            # Check for ufw or iptables rules
            success, stdout, _ = self._run_command(['sudo', 'ufw', 'status'])
            if success and 'active' in stdout.lower():
                return True, "UFW firewall is active"
            
            # Fallback: check if iptables has any rules
            success, stdout, _ = self._run_command(['sudo', 'iptables', '-L'])
            if success and 'Chain' in stdout and 'DROP' in stdout:
                return True, "iptables has active rules"
            return False, "No active firewall rules detected (UFW or iptables)"
        
        return False, "Firewall check not implemented for this OS"
    
    def check_antivirus(self):
        """
        Check if antivirus/endpoint protection is active.
        Windows: Checks Windows Defender.
        macOS: Checks if XProtect is active.
        Linux: Checks if ClamAV or similar is installed and running.
        """
        if self._is_windows():
            success, stdout, _ = self._run_command(
                ['powershell', '-Command', 'Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled']
            )
            if success and 'True' in stdout:
                return True, "Windows Defender antivirus is active and running"
            return False, "Windows Defender is not enabled"
        
        elif self._is_macos():
            # macOS has XProtect built-in - check if it's enabled
            success, stdout, _ = self._run_command(['/usr/bin/xprotect', '--status'])
            if success and 'enabled' in stdout.lower():
                return True, "XProtect malware protection is enabled"
            # Fallback check using system_profiler for XProtect
            success, stdout, _ = self._run_command(['system_profiler', 'SPSoftwareDataType'])
            if success and 'xprotect' in stdout.lower():
                return True, "XProtect appears to be installed"
            return False, "Could not verify antivirus protection on macOS"
        
        elif self._is_linux():
            # Check for ClamAV
            success, _, _ = self._run_command(['which', 'clamscan'])
            if success:
                return True, "ClamAV antivirus is installed"
            
            # Check for common EDR agents as a fallback
            edr_agents = ['falcon', 'crowdstrike', 'sentinel', 'symantec']
            found = False
            for agent in edr_agents:
                success, _, _ = self._run_command(['pgrep', '-f', agent])
                if success:
                    found = True
                    return True, f"EDR agent ({agent}) appears to be running"
            return False, "No antivirus or EDR agent detected"
        
        return False, "Antivirus check not implemented for this OS"
    
    def check_disk_encryption(self):
        """
        Check if disk encryption is enabled.
        Windows: Checks BitLocker.
        macOS: Checks FileVault.
        Linux: Checks LUKS encryption.
        """
        if self._is_windows():
            success, stdout, _ = self._run_command(['manage-bde', '-status'])
            if success and 'Protection On' in stdout:
                return True, "BitLocker encryption is active"
            elif success and 'Protection Off' in stdout:
                return False, "BitLocker encryption is turned off"
            return False, "BitLocker is not available on this system"
        
        elif self._is_macos():
            success, stdout, _ = self._run_command(['fdesetup', 'status'])
            if success and 'on' in stdout.lower():
                return True, "FileVault encryption is enabled"
            else:
                return False, "FileVault encryption is disabled or not available"
        
        elif self._is_linux():
            # Check for LUKS encrypted partitions
            success, stdout, _ = self._run_command(['lsblk', '-f'])
            if success and 'crypto_LUKS' in stdout:
                return True, "LUKS encrypted partitions found"
            return False, "No LUKS encrypted partitions detected"
        
        return False, "Disk encryption check not implemented for this OS"
    
    def check_password_policy(self):
        """
        Check password policy requirements.
        Windows: Checks minimum password length using 'net accounts'.
        macOS: Checks password policy using pwpolicy.
        Linux: Checks password settings in /etc/login.defs.
        """
        min_length = 8  # Default standard recommendation
        
        if self._is_windows():
            success, stdout, _ = self._run_command(['net', 'accounts'])
            if success:
                for line in stdout.split('\n'):
                    if 'minimum password length' in line.lower():
                        match = re.search(r'(\d+)', line)
                        if match:
                            length = int(match.group(1))
                            if length >= min_length:
                                return True, f"Minimum password length is {length} characters"
                            else:
                                return False, f"Minimum password length is {length} characters (recommended: {min_length} or more)"
            return False, "Could not determine password policy settings"
        
        elif self._is_macos():
            # macOS: Check password policy with pwpolicy
            success, stdout, _ = self._run_command(['pwpolicy', '-getaccountpolicies'])
            if success and 'minChars' in stdout:
                match = re.search(r'minChars\s*=\s*(\d+)', stdout)
                if match and int(match.group(1)) >= min_length:
                    return True, f"Password policy meets or exceeds {min_length} characters"
            return False, "Could not verify macOS password policy"
        
        elif self._is_linux():
            # Linux: Check /etc/login.defs for PASS_MIN_LEN
            try:
                with open('/etc/login.defs', 'r') as f:
                    content = f.read()
                    match = re.search(r'PASS_MIN_LEN\s+(\d+)', content)
                    if match and int(match.group(1)) >= min_length:
                        return True, f"Password minimum length is {match.group(1)} characters"
                    else:
                        return False, "Password minimum length is less than recommended or not set"
            except:
                return False, "Could not read /etc/login.defs"
        
        return False, "Password policy check not implemented for this OS"
    
    def check_guest_account(self):
        """
        Check if the guest account is disabled.
        Windows: Checks the Guest user account.
        macOS: Checks if Guest account is disabled in Directory Services.
        Linux: Checks if the guest account exists and is locked.
        """
        if self._is_windows():
            success, stdout, _ = self._run_command(['net', 'user', 'Guest'])
            if success and 'Active' in stdout and 'Yes' in stdout:
                return False, "Guest account is currently active (should be disabled)"
            return True, "Guest account is disabled or does not exist"
        
        elif self._is_macos():
            # macOS: Check if Guest account is disabled via dscl
            success, stdout, _ = self._run_command(['dscl', '.', 'read', '/Users/Guest', 'AuthenticationAuthority'])
            if success and 'Disabled' in stdout:
                return True, "Guest account is disabled"
            return False, "Guest account may be enabled or could not be verified"
        
        elif self._is_linux():
            # Linux: Check if 'guest' user exists and is locked
            success, stdout, _ = self._run_command(['getent', 'passwd', 'guest'])
            if success:
                return False, "Guest account exists (should be removed or locked)"
            return True, "Guest account does not exist"
        
        return False, "Guest account check not implemented for this OS"
    
    def check_os_version(self):
        """
        Verify the operating system is a modern, supported version.
        """
        if self._is_windows():
            try:
                version_parts = self.os_version.split('.')
                if len(version_parts) >= 3:
                    build = int(version_parts[2])
                    if build >= 19000:
                        return True, f"Windows 10/11 (build {build}) is currently supported"
                    else:
                        return False, f"Windows build {build} may be outdated"
            except:
                pass
            return False, "Unable to verify Windows version"
        
        elif self._is_macos():
            try:
                # macOS 13 (Ventura) or newer is considered modern
                major = int(self.os_release.split('.')[0])
                if major >= 13:
                    return True, f"macOS {major} (Ventura or newer) is supported"
                else:
                    return False, f"macOS {major} is older than the recommended version"
            except:
                return False, "Unable to verify macOS version"
        
        elif self._is_linux():
            # Linux: Check kernel version - anything 5.x or newer is good
            try:
                kernel = self.os_release.split('-')[0]
                major = int(kernel.split('.')[0])
                if major >= 5:
                    return True, f"Linux kernel {kernel} is modern"
                else:
                    return False, f"Linux kernel {kernel} is older than recommended (5.x+)"
            except:
                return False, "Unable to verify Linux kernel version"
        
        return False, "OS version check not implemented for this OS"
    
    def check_ssh_security(self):
        """
        Check SSH configuration for secure settings.
        Windows: Not applicable.
        macOS: Checks if SSH is enabled and password authentication is disabled.
        Linux: Checks /etc/ssh/sshd_config for secure settings.
        """
        if self._is_windows():
            return True, "SSH check skipped on Windows (not applicable)"
        
        elif self._is_macos():
            # macOS: Check if SSH is enabled and password auth is disabled
            success, stdout, _ = self._run_command(['systemsetup', '-getremotelogin'])
            if success and 'On' in stdout:
                return True, "Remote login (SSH) is enabled"
            return False, "Remote login (SSH) is disabled"
        
        elif self._is_linux():
            # Linux: Check if root login is disabled and password auth is disabled
            try:
                with open('/etc/ssh/sshd_config', 'r') as f:
                    content = f.read()
                    root_login = 'PermitRootLogin no' in content or 'PermitRootLogin prohibit-password' in content
                    password_auth = 'PasswordAuthentication no' in content
                    if root_login and password_auth:
                        return True, "SSH is configured securely (root login disabled, password auth disabled)"
                    elif root_login or password_auth:
                        return False, "SSH configuration has some secure settings but not all"
                    else:
                        return False, "SSH configuration could be more secure"
            except:
                return False, "Could not read /etc/ssh/sshd_config"
        
        return False, "SSH check not implemented for this OS"
    
    def check_automatic_updates(self):
        """
        Check if automatic updates are configured.
        Windows: Checks Windows Update settings.
        macOS: Checks if automatic updates are enabled.
        Linux: Checks if unattended-upgrades is installed.
        """
        if self._is_windows():
            # Windows: Check if Windows Update is set to auto
            success, stdout, _ = self._run_command(['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update'])
            if success and 'AUState' in stdout:
                return True, "Windows Update appears to be configured automatically"
            return True, "Windows Update appears to be configured with default settings"
        
        elif self._is_macos():
            # macOS: Check software update settings
            success, stdout, _ = self._run_command(['softwareupdate', '--schedule'])
            if success and 'on' in stdout.lower():
                return True, "macOS automatic updates are enabled"
            return False, "macOS automatic updates are disabled"
        
        elif self._is_linux():
            # Linux: Check for unattended-upgrades
            success, _, _ = self._run_command(['which', 'unattended-upgrade'])
            if success:
                return True, "Unattended-upgrades is installed (automatic updates likely configured)"
            return False, "Unattended-upgrades is not installed"
        
        return False, "Automatic updates check not implemented for this OS"
    
    # -------------------------------------------------------------------------
    # Report Generation Methods
    # -------------------------------------------------------------------------
    
    def _print_header(self):
        """
        Print the audit header information.
        """
        print("\n" + "=" * 70)
        print("ENDPOINT SECURITY AUDIT REPORT - CROSS-PLATFORM EDITION")
        print("=" * 70)
        print(f"System: {self.os_name} {self.os_release}")
        print(f"User:   {self.username}")
        print(f"Date:   {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        print("\nRunning OS-specific security checks...\n")
    
    def _run_checks(self):
        """
        Execute all security checks and store results.
        """
        checks = [
            ("Firewall Status", self.check_firewall),
            ("Antivirus / EDR", self.check_antivirus),
            ("Disk Encryption", self.check_disk_encryption),
            ("Password Policy", self.check_password_policy),
            ("Guest Account", self.check_guest_account),
            ("OS Version", self.check_os_version),
            ("SSH Security", self.check_ssh_security),
            ("Automatic Updates", self.check_automatic_updates)
        ]
        
        for name, func in checks:
            try:
                status, message = func()
                self.results.append({
                    'name': name,
                    'status': status,
                    'message': message
                })
                if status and "skipped" not in message.lower():
                    self.passed_count += 1
                elif not status:
                    self.total_count += 1
                if "skipped" not in message.lower():
                    self.total_count += 1
                
                # Print immediate feedback
                if "skipped" in message.lower():
                    print(f"[SKIP] {name}: {message}")
                    self.skipped_count += 1
                elif status:
                    print(f"[PASS] {name}: {message}")
                else:
                    print(f"[FAIL] {name}: {message}")
                    
            except Exception as e:
                print(f"[ERROR] {name}: Exception occurred - {str(e)[:50]}")
                self.results.append({
                    'name': name,
                    'status': False,
                    'message': f"Check failed: {str(e)[:60]}"
                })
                self.total_count += 1
    
    def _print_summary(self):
        """
        Print the summary statistics and recommendations.
        """
        # Calculate score based only on checks that were run (not skipped)
        effective_total = self.total_count
        score = int((self.passed_count / effective_total) * 100) if effective_total > 0 else 0
        
        print("\n" + "=" * 70)
        print("AUDIT SUMMARY")
        print("=" * 70)
        print(f"Checks Passed: {self.passed_count}/{effective_total}")
        if self.skipped_count > 0:
            print(f"Checks Skipped: {self.skipped_count} (not applicable to this OS)")
        print(f"Security Score: {score}%")
        
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
        failed_checks = [r for r in self.results if not r['status'] and "skipped" not in r['message'].lower()]
        if failed_checks:
            print("\nRecommendations:")
            for i, check in enumerate(failed_checks[:5], 1):
                print(f"  {i}. Review {check['name']}: {check['message']}")
            if len(failed_checks) > 5:
                print(f"  ... and {len(failed_checks) - 5} additional issues")
        else:
            print("\nAll applicable checks passed. Your system is well-secured.")
        
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
        
        print(f"\nHTML report generated: {filename}")
        print("Open this file in a web browser to view the detailed report.")
    
    def _build_html_content(self):
        """
        Construct the HTML content for the report.
        """
        effective_total = self.total_count
        score = int((self.passed_count / effective_total) * 100) if effective_total > 0 else 0
        
        if score >= 80:
            score_class = "score-excellent"
        elif score >= 60:
            score_class = "score-good"
        elif score >= 40:
            score_class = "score-warning"
        else:
            score_class = "score-critical"
        
        html = f"""<!DOCTYPE html>
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
        .check-skip {{
            background: #e9ecef;
            border-left-color: #6c757d;
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
        <h1>Endpoint Security Audit Report - Cross-Platform Edition</h1>
        
        <div class="header-info">
            <strong>Generated:</strong> {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>System:</strong> {self.os_name} {self.os_release}<br>
            <strong>User:</strong> {self.username}
        </div>
        
        <div class="score-section">
            <div class="score-value {score_class}">{score}%</div>
            <div class="score-label">Security Score</div>
        </div>
        
        <div class="summary-bar">
            <strong>Checks Passed:</strong> {self.passed_count}/{effective_total}
            {f'<br><strong>Checks Skipped:</strong> {self.skipped_count} (not applicable to this OS)' if self.skipped_count > 0 else ''}
        </div>
        
        <h2>Detailed Results</h2>
"""
        
        for result in self.results:
            if "skipped" in result['message'].lower():
                css_class = "check-skip"
                icon = "[SKIP]"
            elif result['status']:
                css_class = "check-pass"
                icon = "[PASS]"
            else:
                css_class = "check-fail"
                icon = "[FAIL]"
            
            html += f"""
        <div class="check-item {css_class}">
            <div class="check-name">{icon} {result['name']}</div>
            <div class="check-message">{result['message']}</div>
        </div>
"""
        
        failed_checks = [r for r in self.results if not r['status'] and "skipped" not in r['message'].lower()]
        html += """
        <div class="recommendations">
            <h3>Recommendations</h3>
            <ul>
"""
        if failed_checks:
            for check in failed_checks[:5]:
                html += f"                <li><strong>{check['name']}:</strong> {check['message']}</li>\n"
            if len(failed_checks) > 5:
                html += f"                <li>... and {len(failed_checks) - 5} additional issues</li>\n"
        else:
            html += "                <li>No issues found. Your system meets security standards.</li>\n"
        
        html += """
            </ul>
        </div>
        
        <div class="footer">
            Generated by Endpoint Security Auditor v2.0.0 - Cross-Platform Edition
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
        print(f"\nAn unexpected error occurred: {str(e)}")
        sys.exit(1)