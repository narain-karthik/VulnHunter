# VulnHunter
### Enterprise-Grade Automated Vulnerability Assessment and Penetration Testing Framework

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Testing](https://img.shields.io/badge/Security-VAPT%20Framework-red.svg)](https://github.com/narain-karthik/VulnHunter)
[![Metasploit](https://img.shields.io/badge/Metasploit-3758%20Modules-darkred.svg)](https://metasploit.com/)
[![2FA Security](https://img.shields.io/badge/2FA-OTP%20Email%20Auth-orange.svg)](https://github.com/narain-karthik/VulnHunter)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)](https://github.com/narain-karthik/VulnHunter)

## Overview

VulnHunter is a comprehensive security testing framework designed for professional vulnerability assessment and penetration testing (VAPT) across multiple attack surfaces. Built with enterprise-grade architecture, it integrates advanced security tools, automated exploit databases, two-factor authentication, and professional reporting capabilities to deliver thorough security assessments.

### 🎯 Key Capabilities

- **Enterprise Authentication**: Two-factor authentication (2FA) with email OTP verification
- **Multi-Domain Security Testing**: Network Infrastructure, Web Applications, Cloud Environments, and APIs
- **Advanced Exploit Integration**: 3,758 Metasploit modules + 46,000+ Exploit-DB entries
- **Automated Tool Management**: Intelligent dependency checking and automatic installation
- **Professional Reporting**: Executive summaries, technical findings, and remediation recommendations
- **Enterprise Ready**: Session persistence, evidence collection, and compliance reporting

---

## 🚀 Features

### Enterprise Authentication System
- **🔐 Two-Factor Authentication**: Email OTP verification with professional HTML templates
- **🛡️ Advanced Security**: SHA-256 password hashing with salt and lockout protection
- **📧 SMTP Integration**: Gmail-based OTP delivery with TLS encryption
- **🔒 Session Management**: Failed attempt tracking and automatic security lockouts

### Security Testing Domains
- **🌐 Network VAPT**: Infrastructure security assessment with port scanning, service enumeration, and vulnerability identification
- **💻 Web Application VAPT**: OWASP Top 10 focused testing with automated vulnerability discovery
- **☁️ Cloud VAPT**: Multi-cloud security evaluation (AWS, Azure, GCP) with configuration assessment
- **🔌 API VAPT**: REST/GraphQL API security testing with authentication bypass and injection testing

### Advanced Tooling
- **🛠️ Metasploit Integration**: Complete framework with 3,758 modules (2,212 exploits, 867 auxiliary, 368 post-exploitation)
- **🗄️ Exploit Database**: 46,000+ real-world exploits with CVE mapping and manual testing guidance
- **🔧 Automatic Installation**: Smart dependency management with apt-get and pip3 support
- **📊 Tool Coverage**: 57 integrated security tools with intelligent fallback mechanisms

### Professional Reporting
- **📋 Executive Summaries**: Business impact analysis with risk categorization
- **📄 Technical Reports**: Detailed vulnerability findings with proof-of-concept evidence
- **🎨 Multiple Formats**: PDF, HTML, JSON, and plain text output options
- **🔍 Evidence Collection**: Screenshots, command outputs, and exploitation artifacts

---

## 📦 Installation

### Prerequisites
- Python 3.11 or higher
- Linux/Unix environment (Ubuntu, Debian, Kali Linux)
- Root/sudo access for tool installation

### Quick Start
```bash
# Clone the repository
git clone https://github.com/narain-karthik/VulnHunter.git
cd VulnHunter

# Install core Python dependencies  
pip3 install colorama jinja2 tabulate requests reportlab weasyprint markdown

# Launch VulnHunter
python3 main.py

# Check tool dependencies
python3 main.py
# Select option 5: Tool Dependencies Check
# Select option 6: Auto-Install Missing Tools
```

### Advanced Installation
```bash
# Install additional security tools
sudo apt-get update
sudo apt-get install nmap masscan nikto dirb sqlmap jq wget

# Install Python security libraries
pip3 install python-nmap dnspython beautifulsoup4 paramiko scapy

# Test OTP authentication system
python3 test_otp_authentication.py

# Verify installation
python3 main.py
```

---

## 🎮 Usage

### Interactive Mode (Recommended)
```bash
python3 main.py
```

**Two-Factor Authentication Required:**
- Username: WhiteDevil  
- Password: [Configured securely]
- OTP: 6-digit code sent to registered email

**Main Menu Options:**
1. **Network VAPT** - Infrastructure security assessment
2. **Web Application VAPT** - Web security testing
3. **Cloud VAPT** - Cloud infrastructure assessment
4. **API VAPT** - API security validation
5. **Tool Dependencies Check** - Verify security tools
6. **Auto-Install Missing Tools** - Automatic tool installation
7. **Exit** - Exit application

### Command Line Mode
```bash
# Network assessment
python3 main.py --type network --target 192.168.1.0/24

# Web application testing
python3 main.py --type web --target https://example.com

# API security testing
python3 main.py --type api --target https://api.example.com

# Cloud assessment with configuration
python3 main.py --type cloud --target aws --config examples/cloud-config.json
```

### Advanced Options
```bash
# Verbose output with detailed logging
python3 main.py --type network --target 10.0.0.0/8 --verbose

# Custom output directory
python3 main.py --type web --target https://app.example.com --output-dir /tmp/vapt-results

# Configuration-driven assessments
python3 main.py --type network --config examples/network-config.json
```

---

## 🔬 Assessment Methodology

VulnHunter follows a structured 5-phase VAPT methodology:

### Phase 1: Planning and Scope Definition
- Target identification and scope validation
- Assessment type selection and configuration
- Tool availability verification
- Session initialization and logging setup

### Phase 2: Reconnaissance and Information Gathering
- **Passive Reconnaissance**: OSINT collection, domain enumeration, public data gathering
- **Active Reconnaissance**: Port scanning, service detection, technology fingerprinting
- **Network Mapping**: Topology discovery, host enumeration, service identification

### Phase 3: Vulnerability Assessment
- **Automated Scanning**: Comprehensive vulnerability detection across all targets
- **Manual Verification**: Expert validation of automated findings
- **Risk Classification**: CVSS scoring and business impact assessment
- **False Positive Elimination**: Manual verification of critical findings

### Phase 4: Penetration Testing and Exploitation
- **Exploit Selection**: CVE-to-exploit mapping with success rate analysis
- **Manual Testing**: Guided exploitation with step-by-step instructions
- **Post-Exploitation**: Privilege escalation, lateral movement, and persistence
- **Evidence Collection**: Proof-of-concept development and impact demonstration

### Phase 5: Reporting and Remediation
- **Executive Summary**: Business impact analysis and risk overview
- **Technical Findings**: Detailed vulnerability descriptions with remediation steps
- **Evidence Documentation**: Screenshots, command outputs, and exploitation artifacts
- **Remediation Roadmap**: Prioritized action items with implementation guidance

---

## 🛠️ Tool Integration

### Core Security Tools
| Category | Tools | Purpose |
|----------|-------|---------|
| **Network** | nmap, masscan, netdiscover | Port scanning and host discovery |
| **Web** | nikto, dirb, sqlmap, gobuster | Web vulnerability assessment |
| **SSL/TLS** | sslscan, testssl.sh, openssl | Cryptographic security testing |
| **API** | curl, jq, postman | API security validation |
| **Cloud** | aws-cli, scout-suite, prowler | Cloud security assessment |

### Exploit Frameworks
- **Metasploit Framework**: 3,758 modules with automated exploitation
- **Exploit-DB**: 46,000+ exploits with manual testing guidance
- **Custom Exploits**: Tailored payloads for specific vulnerabilities

### Automatic Installation
VulnHunter includes intelligent dependency management:

```bash
# Check current tool coverage
python3 main.py
# Select option 5: Tool Dependencies Check

# Automatic installation
python3 main.py
# Select option 6: Auto-Install Missing Tools
# Choose option 1: Auto-install missing tools
```

**Installation Support:**
- ✅ System packages via `apt-get`
- ✅ Python packages via `pip3`
- ✅ Installation verification and testing
- ✅ Comprehensive success/failure reporting
- ⚠️ Manual guidance for complex tools

---

## 📊 Reporting

### Report Types

#### 1. Executive Summary
- Business impact analysis
- Risk level distribution
- Compliance mapping (OWASP, NIST, ISO 27001)
- Executive recommendations

#### 2. Technical Findings
- Detailed vulnerability descriptions
- Proof-of-concept evidence
- Exploitation steps and impact
- Remediation instructions with code examples

#### 3. Evidence Collection
- Command outputs and tool results
- Network diagrams and attack paths
- Screenshots and visual evidence
- Configuration files and system information

### Output Formats
- **PDF Reports**: Professional formatting with executive summaries
- **HTML Reports**: Interactive findings with embedded evidence
- **JSON Export**: Machine-readable data for integration
- **Plain Text**: Console-friendly summaries

### Sample Report Structure
```
VulnHunter Security Assessment Report
├── Executive Summary
│   ├── Assessment Overview
│   ├── Risk Summary
│   └── Business Recommendations
├── Technical Findings
│   ├── Critical Vulnerabilities
│   ├── High-Risk Issues
│   ├── Medium-Risk Issues
│   └── Low-Risk Issues
├── Penetration Testing Results
│   ├── Successful Exploits
│   ├── Post-Exploitation Evidence
│   └── Impact Assessment
└── Remediation Roadmap
    ├── Immediate Actions
    ├── Short-term Improvements
    └── Long-term Security Strategy
```

---

## 📁 Project Structure

```
VulnHunter/
├── core/                      # Core VAPT framework
│   ├── vapt_manager.py       # Central orchestration
│   ├── planning.py           # Phase 1: Planning
│   ├── reconnaissance.py     # Phase 2: Reconnaissance
│   ├── vulnerability_assessment.py  # Phase 3: Vulnerability Assessment
│   ├── penetration_testing.py      # Phase 4: Penetration Testing
│   └── reporting.py          # Phase 5: Reporting
├── modules/                   # VAPT type implementations
│   ├── network_vapt.py       # Network security testing
│   ├── web_vapt.py           # Web application testing
│   ├── cloud_vapt.py         # Cloud security assessment
│   ├── api_vapt.py           # API security testing
│   ├── metasploit_integration.py  # Metasploit framework
│   └── exploitdb_integration.py   # Exploit-DB integration
├── auth/                      # Authentication system
│   ├── __init__.py           # Authentication module
│   ├── authentication.py     # 2FA authentication system
│   └── otp_email.py          # OTP email verification
├── utils/                     # Utility functions
│   ├── tool_checker.py       # Dependency management
│   ├── output_formatter.py   # Console formatting
│   └── session_manager.py    # Session persistence
├── config/                    # Configuration files
│   └── tools.json            # Tool definitions
├── templates/                 # Report templates
│   └── report_template.html  # HTML report template
├── examples/                  # Sample configurations
│   ├── network-config.json   # Network assessment config
│   └── web-config.json       # Web assessment config
├── metasploit_modules/        # Metasploit integration
│   ├── exploits/             # Exploit modules (2,212 modules)
│   ├── auxiliary/            # Auxiliary modules (867 modules)
│   ├── payloads/             # Payload modules
│   ├── post/                 # Post-exploitation modules (368 modules)
│   └── module_database.py    # Module management
├── main.py                    # Main application entry point
├── test_otp_authentication.py # OTP authentication test suite
├── test_authentication.py    # Authentication test script
├── README.md                  # Project documentation
├── OTP_AUTHENTICATION_GUIDE.md # OTP setup and usage guide
├── VulnHunter_User_Manual.md # Comprehensive user manual
├── VulnHunter_User_Manual.pdf # PDF user manual
├── pyproject.toml            # Python project configuration
├── uv.lock                   # Dependency lock file
└── vapt-dependencies.txt     # Installation guide
```

---

## 🔧 Configuration

### Network Assessment Configuration
```json
{
  "target": "192.168.1.0/24",
  "scan_type": "comprehensive",
  "ports": "1-65535",
  "timing": "T4",
  "scripts": ["vuln", "default", "discovery"],
  "output_formats": ["html", "json"],
  "exploit_integration": true
}
```

### Web Assessment Configuration
```json
{
  "target": "https://example.com",
  "scope": ["https://example.com/*"],
  "authentication": {
    "type": "cookie",
    "credentials": "session=abc123"
  },
  "tests": ["owasp_top10", "custom_payloads"],
  "recursion_depth": 3,
  "report_format": "pdf"
}
```

---

## 🚨 Important Disclaimers

### Legal and Ethical Use
⚠️ **VulnHunter is designed for authorized security testing only**

- ✅ **Authorized Testing**: Only test systems you own or have explicit written permission to test
- ✅ **Professional Use**: Ideal for security consultants, penetration testers, and IT security teams
- ✅ **Educational Purpose**: Suitable for cybersecurity training and research environments
- ❌ **Unauthorized Testing**: Never use against systems without proper authorization
- ❌ **Malicious Activities**: This tool is not intended for illegal or unethical purposes

### Responsibility Statement
Users are solely responsible for ensuring their use of VulnHunter complies with all applicable laws, regulations, and organizational policies. The developers assume no responsibility for misuse of this tool.

---

## 🤝 Contributing

We welcome contributions to improve VulnHunter's capabilities:

### Development Guidelines
1. **Code Style**: Follow PEP 8 standards
2. **Documentation**: Update README.md and inline comments
3. **Testing**: Verify functionality across supported platforms
4. **Security**: Follow secure coding practices

### Contribution Process
1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Update documentation
5. Submit a pull request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🆘 Support

### Documentation
- **User Manual**: VulnHunter_User_Manual.pdf (Comprehensive 75+ page guide)
- **OTP Authentication Guide**: OTP_AUTHENTICATION_GUIDE.md
- **Project Repository**: https://github.com/narain-karthik/VulnHunter.git
- **Installation Guide**: vapt-dependencies.txt
- **API Documentation**: Technical implementation details
- **Video Tutorials**: Step-by-step assessment walkthroughs

### Community Support
- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Join community discussions and share experiences
- **Professional Support**: Contact for enterprise support and custom development

---

## 🔄 Version History

### Latest Release (July 26, 2025)
- **Enterprise 2FA Authentication**: Email OTP verification with professional HTML templates
- **Enhanced Tool Installation**: Automatic dependency management with verification
- **Professional PDF Reporting**: Executive summaries with detailed technical findings
- **Exploit-DB Integration**: 46,000+ exploits with manual testing guidance
- **Metasploit Framework**: Complete integration with 3,758 security modules
- **Multi-Domain Support**: Network, Web, Cloud, and API security testing

### Development Roadmap
- **Machine Learning Integration**: Automated vulnerability prioritization
- **Cloud-Native Support**: Kubernetes and container security testing
- **Compliance Reporting**: SOC 2, PCI DSS, and HIPAA assessment templates
- **API Expansion**: RESTful API for CI/CD integration

---

*VulnHunter - Professional Security Testing Made Simple*
