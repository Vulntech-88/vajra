"""
Discovery Scanner Module
Identifies live hosts using ping sweeps, ARP requests, TCP/UDP port scans
"""
import json
import logging
import socket
import subprocess
import threading
import time
import ipaddress
import re
import os
import ssl
import struct
import random
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import requests
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional, Union

try:
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp, sr1, send
    from scapy.layers.inet import IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WARNING] Scapy not available. Some advanced features will be disabled.")

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("[WARNING] dnspython not available. DNS enumeration will be disabled.")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("[WARNING] python-nmap not available. Nmap integration will be disabled.")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("[WARNING] python-whois not available. WHOIS lookup will be disabled.")


class DiscoveryScanner:
    def __init__(self, target, timeout=3, max_threads=100, rate_limit=0.01):
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.rate_limit = rate_limit
        
        # Results storage
        self.results = {
            "scan_info": {
                "target": target,
                "timestamp": datetime.now().isoformat(),
                "scanner": "DiscoveryScanner"
            },
            "target_info": {},
            "live_hosts": [],
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "dns_info": {},
            "whois_info": {},
            "scan_statistics": {}
        }
        
        # Port definitions
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443, 9090, 10000, 27017,
            445, 515, 631, 1433, 1521, 2049, 3268, 5060, 5061, 6379, 11211
        ]
        
        # Service name mapping
        self.service_names = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 445: 'microsoft-ds', 993: 'imaps', 995: 'pop3s',
            1433: 'mssql', 1521: 'oracle', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
            5900: 'vnc', 8080: 'http-proxy', 8443: 'https-alt'
        }
        
        # Vulnerability signatures
        self.vuln_signatures = {
            'ftp': ['anonymous', 'vsftpd 2.3.4'],
            'ssh': ['SSH-1.', 'SSH-2.0-OpenSSH_7.[0-3]'],
            'http': ['Server: Apache/2.2', 'Server: nginx/1.0'],
            'ssl': ['SSLv2', 'SSLv3'],
            'smb': ['SMBv1']
        }
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup logging configuration"""
        os.makedirs('logs', exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/discovery.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def run(self):
        """Execute discovery scan"""
        start_time = datetime.now()
        print(f"[Discovery] Starting comprehensive scan for {self.target}")
        
        try:
            # Target resolution and info
            self._resolve_target()
            
            # Discovery scans
            self._ping_sweep()
            self._arp_scan()
            self._tcp_port_scan()
            self._udp_port_scan()
            
            # Additional enumeration
            self._dns_enumeration()
            self._whois_lookup()
            
            # Calculate statistics
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            self.results["scan_statistics"] = {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": round(duration, 2),
                "live_hosts_found": len(self.results["live_hosts"]),
                "open_ports_found": len(self.results["open_ports"]),
                "services_identified": len(self.results["services"]),
                "vulnerabilities_found": len(self.results["vulnerabilities"])
            }
            
            # Save results
            self._save_results()
            
            print(f"[Discovery] Scan completed in {duration:.2f} seconds")
            print(f"[Discovery] Found {len(self.results['live_hosts'])} live hosts")
            print(f"[Discovery] Found {len(self.results['open_ports'])} open ports")
            print(f"[Discovery] Identified {len(self.results['vulnerabilities'])} potential vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Discovery scan failed: {e}")
            self.results["error"] = str(e)
            
        return self.results
    
    def _resolve_target(self):
        """Resolve target information"""
        if self._is_ip_address(self.target):
            self.results["target_info"]["ip"] = self.target
            self.results["target_info"]["type"] = "ip"
            try:
                hostname = socket.gethostbyaddr(self.target)[0]
                self.results["target_info"]["hostname"] = hostname
            except:
                pass
        else:
            try:
                ip = socket.gethostbyname(self.target)
                self.results["target_info"]["ip"] = ip
                self.results["target_info"]["hostname"] = self.target
                self.results["target_info"]["type"] = "hostname"
            except Exception as e:
                self.logger.error(f"Could not resolve hostname: {e}")
                self.results["target_info"]["error"] = "Could not resolve hostname"
                return
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except:
            return False
    
    def _ping_sweep(self):
        """Ping sweep to find live hosts"""
        print(f"[Discovery] Starting ping sweep on {self.target}")
        
        target_ip = self.results["target_info"].get("ip")
        if not target_ip:
            return
            
        try:
            # If it's a single IP, just ping it
            if self._is_ip_address(self.target) and '/' not in self.target:
                if self._ping_host(target_ip):
                    self.results["live_hosts"].append({
                        "ip": target_ip,
                        "method": "ping",
                        "response_time": "unknown"
                    })
                return
            
            # For subnet discovery
            try:
                network = ipaddress.IPv4Network(f"{target_ip}/24", strict=False)
                if network.num_addresses > 256:
                    # Limit large subnets
                    hosts_to_scan = random.sample(list(network.hosts()), 100)
                else:
                    hosts_to_scan = list(network.hosts())
                
                def ping_worker(ip):
                    if self._ping_host(str(ip)):
                        return {"ip": str(ip), "method": "ping", "response_time": "unknown"}
                    return None
                
                with ThreadPoolExecutor(max_workers=50) as executor:
                    results = list(executor.map(ping_worker, hosts_to_scan))
                    
                for result in results:
                    if result:
                        self.results["live_hosts"].append(result)
                        
            except Exception as e:
                self.logger.debug(f"Subnet ping sweep failed: {e}")
                
        except Exception as e:
            self.logger.error(f"Ping sweep failed: {e}")
    
    def _ping_host(self, ip: str) -> bool:
        """Ping a single host"""
        try:
            if os.name == 'nt':  # Windows
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '1000', ip],
                    capture_output=True, timeout=3, text=True
                )
            else:  # Unix/Linux
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    capture_output=True, timeout=3, text=True
                )
            return result.returncode == 0
        except:
            return False
    
    def _arp_scan(self):
        """ARP scan for local network discovery"""
        if not SCAPY_AVAILABLE:
            print("[Discovery] ARP scan skipped - Scapy not available")
            return
            
        print(f"[Discovery] Starting ARP scan on {self.target}")
        
        target_ip = self.results["target_info"].get("ip")
        if not target_ip:
            return
            
        try:
            # Only perform ARP scan on local subnets
            network = ipaddress.IPv4Network(f"{target_ip}/24", strict=False)
            if network.num_addresses > 256:
                return  # Skip large networks for ARP
            
            arp_request = ARP(pdst=str(network))
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for element in answered_list:
                host_info = {
                    "ip": element[1].psrc,
                    "mac": element[1].hwsrc,
                    "method": "arp"
                }
                # Add to live hosts if not already present
                if not any(h["ip"] == host_info["ip"] for h in self.results["live_hosts"]):
                    self.results["live_hosts"].append(host_info)
                    
        except Exception as e:
            self.logger.debug(f"ARP scan failed: {e}")
    
    def _tcp_port_scan(self):
        """TCP port scanning"""
        print(f"[Discovery] Starting TCP port scan")
        
        target_ip = self.results["target_info"].get("ip")
        if not target_ip:
            return
            
        def scan_tcp_port(port):
            try:
                time.sleep(self.rate_limit)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                
                if result == 0:
                    service_info = self._detect_service(target_ip, port, 'tcp')
                    port_info = {
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service_info.get("service", "unknown"),
                        "version": service_info.get("version"),
                        "banner": service_info.get("banner")
                    }
                    
                    # Check for vulnerabilities
                    vulns = self._check_vulnerabilities(service_info.get("service"), service_info.get("banner"))
                    if vulns:
                        port_info["vulnerabilities"] = vulns
                        self.results["vulnerabilities"].extend(vulns)
                    
                    return port_info
            except Exception as e:
                self.logger.debug(f"TCP scan error for port {port}: {e}")
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            results = list(executor.map(scan_tcp_port, self.common_ports))
            
        for result in results:
            if result:
                self.results["open_ports"].append(result)
                self.results["services"].append(result)
    
    def _udp_port_scan(self):
        """UDP port scanning"""
        print(f"[Discovery] Starting UDP port scan")
        
        target_ip = self.results["target_info"].get("ip")
        if not target_ip:
            return
            
        # Common UDP ports
        udp_ports = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 1434, 1900, 4500, 5353]
        
        def scan_udp_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(b"", (target_ip, port))
                try:
                    data, addr = sock.recvfrom(1024)
                    sock.close()
                    return {
                        "port": port,
                        "protocol": "udp",
                        "state": "open",
                        "service": self.service_names.get(port, "unknown"),
                        "response": data[:100].decode('utf-8', errors='ignore') if data else None
                    }
                except socket.timeout:
                    sock.close()
                    # UDP timeout might mean open or filtered
                    return {
                        "port": port,
                        "protocol": "udp",
                        "state": "open|filtered",
                        "service": self.service_names.get(port, "unknown")
                    }
            except Exception as e:
                self.logger.debug(f"UDP scan error for port {port}: {e}")
            return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:  # Fewer threads for UDP
            results = list(executor.map(scan_udp_port, udp_ports))
            
        for result in results:
            if result:
                self.results["open_ports"].append(result)
                self.results["services"].append(result)
    
    def _detect_service(self, host: str, port: int, protocol: str) -> Dict[str, Any]:
        """Detect service information"""
        service_info = {
            "service": self.service_names.get(port, "unknown"),
            "version": None,
            "banner": None
        }
        
        try:
            # Banner grabbing
            banner = self._grab_banner(host, port)
            if banner:
                service_info["banner"] = banner[:500]
                service_info["version"] = self._extract_version(banner)
                
        except Exception as e:
            self.logger.debug(f"Service detection error for {host}:{port}: {e}")
            
        return service_info
    
    def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """Grab banner from service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send protocol-specific probes
            if port == 80:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            elif port == 25:
                sock.send(b"EHLO test\r\n")
            elif port in [21, 22]:
                pass  # These send banners automatically
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
            
        except Exception as e:
            self.logger.debug(f"Banner grab failed for {host}:{port}: {e}")
            return None
    
    def _extract_version(self, banner: str) -> Optional[str]:
        """Extract version information from banner"""
        if not banner:
            return None
            
        version_patterns = [
            r'(\d+\.\d+\.?\d*)',
            r'version\s+(\d+\.\d+\.?\d*)',
            r'v(\d+\.\d+\.?\d*)',
            r'/(\d+\.\d+\.?\d*)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return None
    
    def _check_vulnerabilities(self, service: str, banner: str) -> List[Dict[str, Any]]:
        """Check for known vulnerabilities"""
        vulnerabilities = []
        
        if not banner:
            return vulnerabilities
            
        banner_lower = banner.lower()
        
        # Check service-specific vulnerabilities
        service_vulns = self.vuln_signatures.get(service, [])
        for vuln_sig in service_vulns:
            if vuln_sig.lower() in banner_lower:
                vulnerabilities.append({
                    "type": "Known Vulnerable Version",
                    "description": f"Service {service} version contains known vulnerabilities",
                    "signature": vuln_sig,
                    "severity": "High"
                })
        
        # Generic vulnerability checks
        if 'ssh-1.' in banner_lower:
            vulnerabilities.append({
                "type": "Deprecated Protocol",
                "description": "SSH version 1.x is deprecated and insecure",
                "severity": "High"
            })
            
        if 'telnet' in service.lower():
            vulnerabilities.append({
                "type": "Insecure Protocol",
                "description": "Telnet transmits data in plaintext",
                "severity": "Medium"
            })
            
        return vulnerabilities
    
    def _dns_enumeration(self):
        """DNS enumeration"""
        if not DNS_AVAILABLE:
            print("[Discovery] DNS enumeration skipped - dnspython not available")
            return
            
        if self.results["target_info"].get("type") != "hostname":
            return
            
        print("[Discovery] Starting DNS enumeration")
        
        domain = self.target
        dns_info = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "subdomains": []
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            
            # A records
            try:
                answers = resolver.resolve(domain, 'A')
                dns_info["a_records"] = [str(rdata) for rdata in answers]
            except:
                pass
                
            # MX records
            try:
                answers = resolver.resolve(domain, 'MX')
                mx_records = []
                for rdata in answers:
                    try:
                        preference = getattr(rdata, 'preference', 0)
                        exchange = getattr(rdata, 'exchange', str(rdata))
                        mx_records.append(f"{preference} {exchange}")
                    except:
                        mx_records.append(str(rdata))
                dns_info["mx_records"] = mx_records
            except:
                pass
                
            # NS records
            try:
                answers = resolver.resolve(domain, 'NS')
                dns_info["ns_records"] = [str(rdata) for rdata in answers]
            except:
                pass
                
            # TXT records
            try:
                answers = resolver.resolve(domain, 'TXT')
                dns_info["txt_records"] = [str(rdata) for rdata in answers]
            except:
                pass
                
            # Subdomain enumeration
            dns_info["subdomains"] = self._enumerate_subdomains(domain)
            
        except Exception as e:
            self.logger.error(f"DNS enumeration failed: {e}")
            
        self.results["dns_info"] = dns_info
    
    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'blog', 'shop', 'forum', 'support', 'docs',
            'cdn', 'static', 'assets', 'img', 'images', 'js', 'css'
        ]
        
        found_subdomains = []
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
            except:
                continue
                
        return found_subdomains
    
    def _whois_lookup(self):
        """WHOIS information gathering"""
        if not WHOIS_AVAILABLE:
            print("[Discovery] WHOIS lookup skipped - python-whois not available")
            return
            
        print("[Discovery] Starting WHOIS lookup")
        
        try:
            if self._is_ip_address(self.target):
                self.results["whois_info"] = {"type": "ip", "info": "IP WHOIS lookup not implemented"}
            else:
                w = whois.whois(self.target)
                self.results["whois_info"] = {
                    "type": "domain",
                    "registrar": w.registrar,
                    "creation_date": str(w.creation_date) if w.creation_date else None,
                    "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                    "name_servers": w.name_servers,
                    "status": w.status,
                    "country": w.country,
                    "org": w.org
                }
        except Exception as e:
            self.logger.debug(f"WHOIS lookup failed: {e}")
            self.results["whois_info"] = {"error": str(e)}
    
    def _save_results(self):
        """Save results to JSON file"""
        os.makedirs('output', exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_safe = self.target.replace('.', '_').replace('/', '_')
        filename = f"output/discovery_{target_safe}_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
            print(f"[Discovery] Results saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python discovery_scanner.py <target>")
        print("Example: python discovery_scanner.py 192.168.1.1")
        print("Example: python discovery_scanner.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = DiscoveryScanner(target)
    results = scanner.run()
    
    # Print summary
    print("\n" + "="*50)
    print("SCAN SUMMARY")
    print("="*50)
    print(f"Target: {target}")
    print(f"Live Hosts: {len(results['live_hosts'])}")
    print(f"Open Ports: {len(results['open_ports'])}")
    print(f"Services: {len(results['services'])}")
    print(f"Vulnerabilities: {len(results['vulnerabilities'])}")
    print(f"Duration: {results['scan_statistics'].get('duration_seconds', 0)} seconds")