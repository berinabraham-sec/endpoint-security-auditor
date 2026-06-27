# Endpoint Security Auditor

A Python-based security auditing tool for Windows systems that evaluates host hardening configurations against industry best practices. The tool performs 10 security checks and generates both console output and a formatted HTML report.

## Features

- **Firewall Status** - Verifies Windows Firewall is enabled for all network profiles
- **Antivirus Protection** - Checks if Windows Defender is active
- **BitLocker Encryption** - Confirms drive encryption is enabled
- **Password Policy** - Validates minimum password length requirements
- **User Account Control (UAC)** - Ensures UAC is enabled
- **Administrator Accounts** - Counts local admin accounts to prevent privilege creep
- **Guest Account** - Verifies the guest account is disabled
- **Screen Lock** - Checks if screen lock is enabled after inactivity
- **OS Version** - Confirms the system is running a supported Windows version
- **Windows Updates** - Verifies update settings are configured

## Installation

```bash
git clone https://github.com/berinabraham-sec/endpoint-security-auditor.git
cd endpoint-security-auditor