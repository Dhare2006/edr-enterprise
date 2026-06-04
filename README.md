\# 🔒 EDR Lite - Enterprise Endpoint Detection \& Response



\[!\[License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

\[!\[Python](https://img.shields.io/badge/python-3.11+-green.svg)](https://python.org)

\[!\[Security](https://img.shields.io/badge/security-AES--256-red.svg)](https://cryptography.io)



\## 🛡️ Enterprise-Grade Endpoint Detection \& Response System



Real-time process monitoring, threat detection, and automated response for Windows endpoints.



\### ✨ Features



\- 🔍 \*\*Real-time Process Monitoring\*\* - Scans every 3 seconds

\- 🚨 \*\*Threat Detection\*\* - Malware, Miners, Reverse Shells

\- 🔒 \*\*Automated Response\*\* - Auto-terminates malicious processes

\- 👥 \*\*Multi-User Support\*\* - Role-based access control

\- 🔐 \*\*JWT Authentication\*\* - Secure token-based auth

\- 📊 \*\*Dark Theme Dashboard\*\* - Professional UI

\- 📝 \*\*Audit Logging\*\* - Complete security trail

\- ⚡ \*\*Rate Limiting\*\* - Brute force protection

\- 🛡️ \*\*AES-256 Encryption\*\* - Data at rest security



\### 🎯 Detection Capabilities



| Threat Type | Detection Method |

|-------------|------------------|

| Crypto Miners | High CPU usage (>80%) |

| Malware | Process name matching |

| Reverse Shells | Suspicious network ports |

| Ransomware | Known process patterns |

| Suspicious Commands | PowerShell/Cmd patterns |



\### 🚀 Quick Start



\#### Prerequisites

\- Python 3.11+

\- Git

\- Modern web browser



\#### Installation



```bash

\# Clone repository

git clone https://github.com/YOUR\_USERNAME/edr-enterprise.git

cd edr-enterprise



\# Create virtual environment

python -m venv venv

source venv/Scripts/activate  # Windows



\# Install dependencies

pip install -r requirements.txt



\# Run application

python app.py

