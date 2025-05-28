# Vajra Security Scanner

A modular Python-based security scanner that follows a comprehensive workflow for network security assessment.

## Installation

1. Run the setup script:
```bash
chmod +x setup_vajra.sh
./setup_vajra.sh
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Full Scan
```bash
python main.py 192.168.1.1
```

### Individual Module (Future Feature)
```bash
python main.py 192.168.1.1 --module discovery
```

## Workflow Phases

1. **Discovery**: Host and port discovery
2. **Enumeration**: Service detection and banner grabbing
3. **Vulnerability Detection**: CVE matching and exploit search
4. **Deep Scanning**: Credentialed scanning and configuration audit
5. **Web Testing**: OWASP Top 10 and web application security
6. **Compliance**: CIS, PCI-DSS, HIPAA, ISO 27001 checks
7. **Malware Detection**: Signature scanning and IOC detection
8. **Reporting**: Consolidated JSON, HTML, and CSV reports

## Output

- Individual module results: `output/[module]_[target]_[timestamp].json`
- Full scan results: `output/vajra_full_scan_[target]_[timestamp].json`
- Logs: `logs/` directory

## Project Structure

```
vajra/
├── modules/          # Scanner modules
├── utils/           # Helper functions
├── logs/            # Log files
├── output/          # Scan results
├── main.py          # Main controller
└── requirements.txt # Dependencies
```
