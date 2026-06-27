# Endpoint Security Auditor

A cross-platform, Python-based security auditing tool that evaluates host hardening configurations against industry best practices for Windows, macOS, and Linux systems.

The tool performs OS-aware security checks and generates both a detailed console report and a formatted HTML report with actionable recommendations.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Platform Support](#platform-support)
- [Installation](#installation)
- [Usage](#usage)
- [Security Checks](#security-checks)
- [Sample Output](#sample-output)
- [Report Generation](#report-generation)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Limitations](#limitations)
- [Future Roadmap](#future-roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## Overview

The Endpoint Security Auditor is designed to help security engineers, system administrators, and IT professionals quickly assess the security posture of a system. It checks for common misconfigurations and missing controls that could expose a system to risk.

The tool was built with a focus on:
- **Cross-platform compatibility**: Works on Windows, macOS, and Linux without modification.
- **OS-awareness**: Each check is executed only if it applies to the current operating system.
- **Actionable reporting**: Results are presented with clear pass/fail status and specific recommendations for remediation.
- **Modular design**: The codebase is structured to make it easy to add new checks or extend support for additional operating systems.

---

## Key Features

- **Firewall Status** – Verifies the host-based firewall is active (Windows Defender Firewall, macOS Application Firewall, Linux UFW/iptables).
- **Antivirus / Endpoint Protection** – Checks if antivirus or EDR software is installed and active (Windows Defender, macOS XProtect, Linux ClamAV/EDR agents).
- **Disk Encryption** – Confirms full-disk encryption is enabled (BitLocker, FileVault, LUKS).
- **Password Policy** – Validates that minimum password length requirements meet security standards (8 characters or more).
- **Guest Account Status** – Ensures the guest account is disabled to prevent unauthorized access.
- **Operating System Version** – Confirms the system is running a modern, vendor-supported version.
- **SSH Security** – (macOS/Linux) Reviews SSH configuration to ensure secure settings, such as disabled root login and password authentication.
- **Automatic Updates** – Verifies that security updates are configured to install automatically.

---

## Platform Support

| Operating System | Support Status | Key Checks |
|------------------|---------------|------------|
| Windows 10 / 11  | Full           | Firewall, Defender, BitLocker, Password Policy, Guest Account, Updates |
| macOS 13+        | Full           | Firewall, XProtect, FileVault, Password Policy, Guest Account, SSH, Updates |
| Linux (Ubuntu/Debian/RHEL) | Full | Firewall (UFW/iptables), ClamAV/EDR, LUKS, SSH config, Updates |

Checks that do not apply to the current operating system are automatically skipped and clearly noted in the report.

---

## Installation

### Prerequisites
- Python 3.6 or higher
- Git (optional, for cloning the repository)

### Clone the Repository
```bash
git clone https://github.com/berinabraham-sec/endpoint-security-auditor.git
cd endpoint-security-auditor