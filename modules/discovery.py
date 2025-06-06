"""
Discovery Scanner Module - FIXED VERSION
Identifies live hosts using ping sweeps, ARP requests, TCP/UDP port scans
Fixed the contradiction between live hosts and open ports detection
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
                "scanner": "Discovery"
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
        """Execute discovery scan with proper host-port association"""
        start_time = datetime.now()
        self.logger.info(f"[Discovery] Starting comprehensive scan for {self.target}")
        
        try:
            # Target resolution and info
            self._resolve_target()
            
            # Enhanced discovery scans with proper host detection
            self._enhanced_host_discovery()
            
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
            
            self.logger.info(f"[Discovery] Scan completed in {duration:.2f} seconds")
            self.logger.info(f"[Discovery] Found {len(self.results['live_hosts'])} live hosts")
            self.logger.info(f"[Discovery] Found {len(self.results['open_ports'])} open ports")
            self.logger.info(f"[Discovery] Identified {len(self.results['vulnerabilities'])} potential vulnerabilities")
            
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
    
    def _enhanced_host_discovery(self):
        """Enhanced host discovery that properly associates hosts with their open ports"""
        target_ip = self.results["target_info"].get("ip")
        if not target_ip:
            return
            
        self.logger.info(f"[Discovery] Starting enhanced host discovery for {target_ip}")
        
        # Determine if this is a single host or subnet scan
        if self._is_single_host():
            self._discover_single_host(target_ip)
        else:
            self._discover_subnet_hosts(target_ip)
    
    def _is_single_host(self) -> bool:
        """Check if target is a single host (not a subnet)"""
        return ('/' not in self.target and 
                self._is_ip_address(self.target)) or not self._is_ip_address(self.target)
    
    def _discover_single_host(self, target_ip: str):
        """Discover single host using multiple methods"""
        host_info = {
            "ip": target_ip,
            "hostname": self.results["target_info"].get("hostname"),
            "detection_methods": [],
            "open_ports": [],
            "services": []
        }
        
        # Method 1: ICMP Ping
        if self._ping_host(target_ip):
            host_info["detection_methods"].append("icmp_ping")
            self.logger.info(f"[Discovery] Host {target_ip} responds to ICMP ping")
        
        # Method 2: ARP (for local networks)
        if SCAPY_AVAILABLE:
            mac_address = self._arp_ping(target_ip)
            if mac_address:
                host_info["detection_methods"].append("arp")
                host_info["mac_address"] = mac_address
                self.logger.info(f"[Discovery] Host {target_ip} detected via ARP: {mac_address}")
        
        # Method 3: TCP Connect Scan (most reliable for internet hosts)
        open_ports = self._tcp_connect_scan(target_ip)
        if open_ports:
            host_info["detection_methods"].append("tcp_connect")
            host_info["open_ports"] = open_ports
            self.logger.info(f"[Discovery] Host {target_ip} has {len(open_ports)} open TCP ports")
            
            # Add individual port entries to results
            for port_info in open_ports:
                self.results["open_ports"].append(port_info)
                self.results["services"].append(port_info)
        
        # Method 4: UDP Scan (limited)
        udp_ports = self._udp_scan(target_ip)
        if udp_ports:
            if "udp_scan" not in host_info["detection_methods"]:
                host_info["detection_methods"].append("udp_scan")
            host_info["open_ports"].extend(udp_ports)
            
            # Add UDP ports to results
            for port_info in udp_ports:
                self.results["open_ports"].append(port_info)
                self.results["services"].append(port_info)
        
        # If we detected the host by any method, add it to live_hosts
        if host_info["detection_methods"]:
            self.results["live_hosts"].append(host_info)
            self.logger.info(f"[Discovery] Host {target_ip} confirmed live via: {', '.join(host_info['detection_methods'])}")
        else:
            # Host doesn't respond to any detection method
            self.logger.warning(f"[Discovery] Host {target_ip} does not respond to any detection methods")
            # Still add it as a potential host if we resolved it
            if self.results["target_info"].get("hostname"):
                host_info["detection_methods"] = ["dns_resolution"]
                host_info["status"] = "unresponsive"
                self.results["live_hosts"].append(host_info)
    
    def _discover_subnet_hosts(self, target_ip: str):
        """Discover hosts in a subnet"""
        try:
            network = ipaddress.IPv4Network(f"{target_ip}/24", strict=False)
            if network.num_addresses > 256:
                # Limit large subnets
                hosts_to_scan = random.sample(list(network.hosts()), 100)
            else:
                hosts_to_scan = list(network.hosts())
            
            self.logger.info(f"[Discovery] Scanning {len(hosts_to_scan)} hosts in subnet")
            
            def discover_host(ip_addr):
                ip_str = str(ip_addr)
                host_info = {
                    "ip": ip_str,
                    "detection_methods": [],
                    "open_ports": []
                }
                
                # ICMP Ping
                if self._ping_host(ip_str):
                    host_info["detection_methods"].append("icmp_ping")
                
                # ARP for local network
                if SCAPY_AVAILABLE:
                    mac_address = self._arp_ping(ip_str)
                    if mac_address:
                        host_info["detection_methods"].append("arp")
                        host_info["mac_address"] = mac_address
                
                # Quick TCP scan on common ports
                quick_ports = [22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389]
                open_ports = self._quick_tcp_scan(ip_str, quick_ports)
                if open_ports:
                    host_info["detection_methods"].append("tcp_connect")
                    host_info["open_ports"] = open_ports
                
                return host_info if host_info["detection_methods"] else None
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                results = list(executor.map(discover_host, hosts_to_scan))
            
            for result in results:
                if result:
                    self.results["live_hosts"].append(result)
                    # Add ports to main results
                    for port_info in result.get("open_ports", []):
                        self.results["open_ports"].append(port_info)
                        self.results["services"].append(port_info)
                        
        except Exception as e:
            self.logger.error(f"Subnet discovery failed: {e}")
    
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
    
    def _arp_ping(self, ip: str) -> Optional[str]:
        """ARP ping for a single host"""
        if not SCAPY_AVAILABLE:
            return None
            
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc
        except Exception as e:
            self.logger.debug(f"ARP ping failed for {ip}: {e}")
        return None
    
    def _tcp_connect_scan(self, host: str) -> List[Dict[str, Any]]:
        """Comprehensive TCP connect scan"""
        open_ports = []
        
        def scan_tcp_port(port):
            try:
                time.sleep(self.rate_limit)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    service_info = self._detect_service(host, port, 'tcp')
                    port_info = {
                        "ip": host,
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": service_info.get("service", "unknown"),
                        "version": service_info.get("version"),
                        "banner": service_info.get("banner")
                    }
                    
                    # Check for vulnerabilities
                    service_name = service_info.get("service") or "unknown"
                    banner_text = service_info.get("banner") or ""
                    vulns = self._check_vulnerabilities(service_name, banner_text)
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
                open_ports.append(result)
                
        return open_ports
    
    def _quick_tcp_scan(self, host: str, ports: List[int]) -> List[Dict[str, Any]]:
        """Quick TCP scan for subnet discovery"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Faster timeout for subnet scans
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    port_info = {
                        "ip": host,
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": self.service_names.get(port, "unknown")
                    }
                    open_ports.append(port_info)
            except:
                continue
                
        return open_ports
    
    def _udp_scan(self, host: str) -> List[Dict[str, Any]]:
        """UDP port scanning"""
        open_ports = []
        
        # Common UDP ports
        udp_ports = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 1434, 1900, 4500, 5353]
        
        def scan_udp_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(b"", (host, port))
                try:
                    data, addr = sock.recvfrom(1024)
                    sock.close()
                    return {
                        "ip": host,
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
                        "ip": host,
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
                open_ports.append(result)
                
        return open_ports
    
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
            self.logger.debug("[Discovery] DNS enumeration skipped - dnspython not available")
            return
            
        if self.results["target_info"].get("type") != "hostname":
            return
            
        self.logger.info("[Discovery] Starting DNS enumeration")
        
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
            self.logger.debug("[Discovery] WHOIS lookup skipped - python-whois not available")
            return
            
        self.logger.info("[Discovery] Starting WHOIS lookup")
        
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
            self.logger.info(f"[Discovery] Results saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")

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
    
    # Print detailed live host information
    if results['live_hosts']:
        print("\nLIVE HOSTS DETAILS:")
        print("-" * 30)
        for host in results['live_hosts']:
            print(f"Host: {host['ip']}")
            if 'hostname' in host and host['hostname']:
                print(f"  Hostname: {host['hostname']}")
            print(f"  Detection Methods: {', '.join(host['detection_methods'])}")
            if 'mac_address' in host:
                print(f"  MAC Address: {host['mac_address']}")
            if 'open_ports' in host and host['open_ports']:
                print(f"  Open Ports: {len(host['open_ports'])}")
                for port in host['open_ports'][:5]:  # Show first 5 ports
                    print(f"    {port['port']}/{port['protocol']} ({port['service']})")
                if len(host['open_ports']) > 5:
                    print(f"    ... and {len(host['open_ports']) - 5} more")
            print()