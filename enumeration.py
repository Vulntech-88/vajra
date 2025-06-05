#!/usr/bin/env python3


import socket
import sys
import threading
import time
import json
import subprocess
import re
import ssl
import requests
import urllib3
from datetime import datetime
from typing import Optional, Dict, List, Any
import struct
import binascii

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Enumerator:
    def __init__(self, target: str):
        self.target = target
        self.ip: Optional[str] = None
        self.results: Dict[str, Any] = {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "host_info": {},
            "open_ports": [],
            "services": {},
            "banners": {},
            "vulnerabilities": {},
            "web_info": {},
            "ssl_info": {},
            "smb_info": {},
            "ssh_info": {},
            "ftp_info": {},
            "dns_info": {},
            "snmp_info": {}
        }
        self.threads: List[threading.Thread] = []
        self.max_threads = 200
        self.timeout = 5
        self.lock = threading.Lock()
        
        # Comprehensive port list (top 2000)
        self.ports = list(range(1, 1024)) + [
            1080, 1194, 1433, 1521, 1723, 2049, 2121, 2222, 2375, 2376, 2379,
            3000, 3306, 3389, 3690, 4369, 4444, 4567, 5000, 5432, 5555, 5672,
            5800, 5900, 5984, 6000, 6379, 6443, 6666, 7000, 7001, 7777, 8000,
            8008, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
            8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099, 8180,
            8443, 8800, 8880, 8888, 9000, 9001, 9002, 9003, 9080, 9090, 9200,
            9300, 9443, 9999, 10000, 11211, 27017, 27018, 27019, 28017, 50000
        ]

    def log(self, message: str, level: str = "INFO"):
        """Enhanced logging with timestamps"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] [{level}] {message}")

    def resolve_target(self) -> bool:
        """Resolve hostname and get basic host info"""
        try:
            self.ip = socket.gethostbyname(self.target)
            self.results["host_info"]["ip"] = self.ip
            
            if self.ip != self.target:
                self.log(f"Resolved {self.target} to {self.ip}")
                self.results["host_info"]["hostname"] = self.target
            
            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(self.ip)[0]
                self.results["host_info"]["reverse_dns"] = hostname
                self.log(f"Reverse DNS: {hostname}")
            except:
                pass
                
            return True
        except socket.gaierror as e:
            self.log(f"Could not resolve {self.target}: {e}", "ERROR")
            return False

    def ping_host(self) -> bool:
        """Check if host is alive"""
        if not self.ip:
            return False
            
        try:
            if sys.platform.startswith('win'):
                cmd = f"ping -n 1 -w 1000 {self.ip}"
            else:
                cmd = f"ping -c 1 -W 1 {self.ip}"
            
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
            alive = result.returncode == 0
            self.results["host_info"]["alive"] = alive
            
            if alive:
                self.log("Host is alive")
            else:
                self.log("Host may be down or filtered", "WARNING")
                
            return alive
        except:
            return True  # Continue anyway

    def scan_port(self, port: int):
        """port scanning with service detection"""
        if not self.ip:
            return
            
        try:
            # TCP Connect scan
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.ip, port))
            
            if result == 0:
                with self.lock:
                    self.results["open_ports"].append(port)
                    self.log(f"Port {port}/tcp open")
                
                # Get banner and service info
                self.get_banner(sock, port)
                self.detect_service(port)
                
            sock.close()
            
        except Exception as e:
            pass

    def get_banner(self, sock: socket.socket, port: int):
        """banner grabbing"""
        if not self.ip:
            return
            
        try:
            # Send appropriate probes based on port
            if port == 80 or port == 8080:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.ip.encode() + b"\r\n\r\n")
            elif port == 443 or port == 8443:
                return  # Handle SSL separately
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            elif port == 25:
                sock.send(b"HELO test\r\n")
            elif port == 110:
                pass  # POP3 sends banner
            elif port == 143:
                pass  # IMAP sends banner
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                with self.lock:
                    self.results["banners"][str(port)] = banner
                    self.log(f"Banner {port}: {banner[:50]}...")
                    
        except:
            pass

    def detect_service(self, port: int):
        """Enhanced service detection"""
        service_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
            139: "netbios", 143: "imap", 161: "snmp", 389: "ldap",
            443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
            8080: "http-proxy", 27017: "mongodb"
        }
        
        service = service_map.get(port, "unknown")
        with self.lock:
            self.results["services"][str(port)] = service

    def enumerate_http(self, port: int):
        """HTTP enumeration"""
        if not self.ip:
            return
            
        try:
            scheme = "https" if port in [443, 8443] else "http"
            url = f"{scheme}://{self.ip}:{port}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            web_info = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "title": "",
                "server": response.headers.get('Server', ''),
                "technologies": []
            }
            
            # Extract title
            title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
            if title_match:
                web_info["title"] = title_match.group(1).strip()
            
            # Detect technologies
            content = response.text.lower()
            if 'wordpress' in content or 'wp-content' in content:
                web_info["technologies"].append("WordPress")
            if 'joomla' in content:
                web_info["technologies"].append("Joomla")
            if 'drupal' in content:
                web_info["technologies"].append("Drupal")
            if 'apache' in response.headers.get('Server', '').lower():
                web_info["technologies"].append("Apache")
            if 'nginx' in response.headers.get('Server', '').lower():
                web_info["technologies"].append("Nginx")
            
            with self.lock:
                self.results["web_info"][str(port)] = web_info
                self.log(f"HTTP {port}: {response.status_code} - {web_info['title']}")
                
        except Exception as e:
            pass

    def enumerate_ssl(self, port: int):
        """SSL/TLS enumeration"""
        if not self.ip:
            return
            
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.ip, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.ip) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    ssl_info = {
                        "version": ssock.version(),
                        "cipher": cipher[0] if cipher else None,
                        "certificate": {
                            "subject": dict(x[0] for x in cert.get('subject', [])),
                            "issuer": dict(x[0] for x in cert.get('issuer', [])),
                            "version": cert.get('version'),
                            "serial_number": cert.get('serialNumber'),
                            "not_before": cert.get('notBefore'),
                            "not_after": cert.get('notAfter')
                        }
                    }
                    
                    with self.lock:
                        self.results["ssl_info"][str(port)] = ssl_info
                        self.log(f"SSL {port}: {ssl_info['version']} - {ssl_info['certificate']['subject'].get('commonName', 'N/A')}")
                        
        except Exception as e:
            pass

    def enumerate_smb(self):
        """SMB enumeration"""
        if not self.ip:
            return
            
        if 445 in self.results["open_ports"] or 139 in self.results["open_ports"]:
            try:
                # Basic SMB info using smbclient if available
                cmd = f"smbclient -L //{self.ip} -N"
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    shares = []
                    for line in result.stdout.split('\n'):
                        if 'Disk' in line or 'IPC' in line:
                            shares.append(line.strip())
                    
                    self.results["smb_info"] = {
                        "shares": shares,
                        "version": "detected"
                    }
                    self.log(f"SMB shares found: {len(shares)}")
                    
            except:
                # Fallback: basic banner grab on port 445
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((self.ip, 445))
                    
                    # SMB negotiate request
                    smb_negotiate = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8'
                    sock.send(smb_negotiate)
                    response = sock.recv(1024)
                    
                    if b'SMB' in response:
                        self.results["smb_info"] = {"detected": True}
                        self.log("SMB service detected")
                    
                    sock.close()
                except:
                    pass

    def enumerate_ssh(self):
        """SSH enumeration"""
        if not self.ip:
            return
            
        if 22 in self.results["open_ports"]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((self.ip, 22))
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
                ssh_info = {
                    "banner": banner,
                    "version": banner.split()[0] if banner else "unknown"
                }
                
                self.results["ssh_info"] = ssh_info
                self.log(f"SSH version: {ssh_info['version']}")
                
                sock.close()
            except:
                pass

    def enumerate_ftp(self):
        """FTP enumeration"""
        if not self.ip:
            return
            
        if 21 in self.results["open_ports"]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((self.ip, 21))
                
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
                # Test anonymous login
                sock.send(b"USER anonymous\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                anonymous = False
                if "230" in response or "331" in response:
                    sock.send(b"PASS anonymous@test.com\r\n")
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    if "230" in response:
                        anonymous = True
                
                ftp_info = {
                    "banner": banner,
                    "anonymous_login": anonymous
                }
                
                self.results["ftp_info"] = ftp_info
                self.log(f"FTP anonymous: {'Yes' if anonymous else 'No'}")
                
                sock.close()
            except:
                pass

    def check_vulnerabilities(self):
        """Basic vulnerability checks"""
        vulns = {}
        
        # Check for common vulnerable services
        for port in self.results["open_ports"]:
            service = self.results["services"].get(str(port), "unknown")
            
            if service == "ftp" and self.results.get("ftp_info", {}).get("anonymous_login"):
                vulns["ftp_anonymous"] = "FTP allows anonymous login"
            
            if service == "telnet":
                vulns["telnet_unencrypted"] = "Telnet uses unencrypted communication"
            
            if port == 139 or port == 445:
                vulns["smb_exposed"] = "SMB service exposed - potential for attacks"
            
            if service == "http" and str(port) in self.results.get("web_info", {}):
                web_info = self.results["web_info"][str(port)]
                server = web_info.get("server", "").lower()
                if "apache/2.2" in server or "apache/2.0" in server:
                    vulns["old_apache"] = "Potentially outdated Apache version"
        
        self.results["vulnerabilities"] = vulns
        if vulns:
            self.log(f"Found {len(vulns)} potential security issues")

    def port_scan(self):
        """Main port scanning function"""
        self.log(f"Scanning {len(self.ports)} ports...")
        
        for i in range(0, len(self.ports), self.max_threads):
            batch = self.ports[i:i+self.max_threads]
            threads = []
            
            for port in batch:
                thread = threading.Thread(target=self.scan_port, args=(port,))
                thread.start()
                threads.append(thread)
            
            for thread in threads:
                thread.join()
        
        self.log(f"Found {len(self.results['open_ports'])} open ports")

    def deep_enumeration(self):
        """Perform deep enumeration on discovered services"""
        self.log("Starting deep enumeration...")
        
        for port in self.results["open_ports"]:
            service = self.results["services"].get(str(port), "unknown")
            
            if service in ["http", "https"] or port in [80, 443, 8080, 8443]:
                self.enumerate_http(port)
            
            if service == "https" or port in [443, 8443]:
                self.enumerate_ssl(port)
        
        # Service-specific enumeration
        self.enumerate_ssh()
        self.enumerate_ftp()
        self.enumerate_smb()

    def generate_summary(self) -> Dict[str, Any]:
        """Generate a summary of findings"""
        summary = {
            "total_ports_scanned": len(self.ports),
            "open_ports_count": len(self.results["open_ports"]),
            "services_identified": len([s for s in self.results["services"].values() if s != "unknown"]),
            "vulnerabilities_found": len(self.results["vulnerabilities"]),
            "web_services": len(self.results["web_info"]),
            "ssl_services": len(self.results["ssl_info"]),
            "risk_level": self.calculate_risk_level()
        }
        return summary

    def calculate_risk_level(self) -> str:
        """Calculate overall risk level based on findings"""
        risk_score = 0
        
        # Add points for open ports
        risk_score += len(self.results["open_ports"]) * 1
        
        # Add points for vulnerabilities
        risk_score += len(self.results["vulnerabilities"]) * 5
        
        # Add points for risky services
        risky_services = ["ftp", "telnet", "smb", "rdp"]
        for port, service in self.results["services"].items():
            if service in risky_services:
                risk_score += 3
        
        # Check for anonymous FTP
        if self.results.get("ftp_info", {}).get("anonymous_login"):
            risk_score += 10
        
        if risk_score >= 20:
            return "HIGH"
        elif risk_score >= 10:
            return "MEDIUM"
        elif risk_score >= 5:
            return "LOW"
        else:
            return "INFO"

    def save_json_report(self, filename: Optional[str] = None):
        """Save comprehensive JSON report to file"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_target = re.sub(r'[^\w\-_.]', '_', self.target)
            filename = f"reports/enumeration_report_{safe_target}_{timestamp}.json"
        
        # Add summary and metadata to results
        report = {
            "metadata": {
                "tool": "Enumeration Scanner",
                "version": "1.0",
                "scan_start": self.results["scan_time"],
                "scan_end": datetime.now().isoformat(),
                "target": self.target,
                "scanner_config": {
                    "max_threads": self.max_threads,
                    "timeout": self.timeout,
                    "ports_scanned": len(self.ports)
                }
            },
            "summary": self.generate_summary(),
            "detailed_results": self.results
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.log(f"JSON report saved to: {filename}")
            return filename
        except Exception as e:
            self.log(f"Failed to save JSON report: {e}", "ERROR")
            return None

    def print_summary(self):
        """Print a concise summary of findings"""
        summary = self.generate_summary()
        
        print("\n" + "="*60)
        print("ENUMERATION SUMMARY")
        print("="*60)
        print(f"Target: {self.target}")
        if self.ip and self.ip != self.target:
            print(f"IP Address: {self.ip}")
        
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Risk Level: {summary['risk_level']}")
        print(f"Open Ports: {summary['open_ports_count']}/{summary['total_ports_scanned']}")
        print(f"Services Identified: {summary['services_identified']}")
        print(f"Vulnerabilities: {summary['vulnerabilities_found']}")
        
        if self.results["open_ports"]:
            print(f"\nOpen Ports: {', '.join(map(str, sorted(self.results['open_ports'])))}")
        
        if self.results["vulnerabilities"]:
            print("\nSecurity Issues Found:")
            for vuln, desc in self.results["vulnerabilities"].items():
                print(f"  - {desc}")
        
        print("\n" + "="*60)

    def run(self):
        """Main execution function"""
        self.log(f"Starting enumeration of {self.target}")
        
        if not self.resolve_target():
            return
        
        self.ping_host()
        self.port_scan()
        
        if self.results["open_ports"]:
            self.deep_enumeration()
            self.check_vulnerabilities()
        else:
            self.log("No open ports found", "WARNING")
        
        # Generate and save report
        self.log("Enumeration complete")
        self.print_summary()
        
        # Save JSON report
        report_file = self.save_json_report()
        if report_file:
            self.log(f"Detailed JSON report available in: {report_file}")
        
        return self.results

def main():
    if len(sys.argv) != 2:
        print("Usage: python enumeration.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    enumerator = Enumerator(target)
    enumerator.run()

if __name__ == "__main__":
    main()