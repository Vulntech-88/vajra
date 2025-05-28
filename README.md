# Vajra Security Scanner

**Vajra** is an open-source, modular Python-based security scanner designed to perform a full-stack assessment of networks and web applications. It integrates various scanning phases such as host discovery, service enumeration, vulnerability assessment, compliance checking, and malware fingerprinting—making it a versatile tool for red teams, blue teams, and developers alike.

---

## 🔍 Features

- **Discovery**: Detects live hosts and open ports using ping sweeps, ARP, TCP/UDP scans.
- **Enumeration**: Identifies running services, grabs banners, and detects versions.
- **Vulnerability Detection**: Matches results with public CVEs and advisories.
- **Deep Scanning**: Credentialed scanning for misconfigurations and missing patches.
- **Web App Testing**: Covers OWASP Top 10, CMS issues, and security misconfigs.
- **Compliance Checking**: Supports checks for CIS, PCI-DSS, HIPAA, ISO 27001.
- **Malware Fingerprinting**: Flags malware indicators and suspicious files.
- **Reporting**: Outputs detailed reports in JSON, HTML, and CSV formats.

---

## 🚀 Getting Started

### 📦 Requirements

- Python 3.8+
- Run `pip install -r requirements.txt` to install dependencies.

### 🔧 Usage

#### Full Scan

```bash
python main.py 192.168.1.1
```

#### Run Specific Module *(coming soon)*

```bash
python main.py 192.168.1.1 --module discovery
```

---

## 🧠 Workflow Overview

```
Discovery → Enumeration → Vulnerability Detection → Deep Scanning (Credentialed)
→ Web App Testing → Compliance Checking → Malware Fingerprinting → Reporting
```

Each module uses output from the previous stage for deeper analysis.

---

## 📁 Output Files

- **Per Module Output**: `output/[module]_[target]_[timestamp].json`
- **Full Scan Report**: `output/vajra_full_scan_[target]_[timestamp].json`
- **Logs**: Stored in the `logs/` directory for debugging and audit trails.

---

## 🗂️ Project Structure

```
vajra/
├── modules/           # All core scanning modules
├── utils/             # Utility functions and shared helpers
├── logs/              # Log output of each module
├── output/            # Scan results and final reports
├── main.py            # Main controller to orchestrate modules
├── requirements.txt   # Python dependencies
└── README.md          # Project documentation
```

---
