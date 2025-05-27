#!/usr/bin/env python3

import sys
import json
import subprocess
import socket
import threading
import time
import ipaddress
import re
import os
import argparse
import ssl
import struct
import random
import hashlib
import dns.rdatatype
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import logging
import dns.resolver
import dns.reversename
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from scapy.sendrecv import sr1, send
from scapy.layers.inet import IP, TCP
from urllib.parse import urljoin, urlparse
import nmap
import whois
from typing import List, Dict, Any, Optional, Union


class Discovery:
    def __init__(self, timeout=3, max_threads=100,
                 rate_limit=0.005, stealth_mode=False):
        self.timeout = timeout
        self.max_threads = max_threads
        self.rate_limit = rate_limit
        self.stealth_mode = stealth_mode

        # Expanded port lists
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443, 9090, 10000, 27017,
            445, 515, 631, 1433, 1521, 2049, 3268, 5060, 5061, 6379, 11211
        ]

        self.top_1000_ports = list(range(1, 1001))
        self.all_ports = list(range(1, 65536))

        # Vulnerability signatures
        self.vuln_signatures = {
            'ftp': ['anonymous', 'vsftpd 2.3.4'],
            'ssh': ['SSH-1.', 'SSH-2.0-OpenSSH_7.[0-3]'],
            'http': ['Server: Apache/2.2', 'Server: nginx/1.0'],
            'ssl': ['SSLv2', 'SSLv3'],
            'smb': ['SMBv1']
        }

        # Service name mapping
        self.service_names = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 445: 'microsoft-ds', 993: 'imaps', 995: 'pop3s',
            1433: 'mssql', 1521: 'oracle', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
            5900: 'vnc', 8080: 'http-proxy', 8443: 'https-alt'
        }

        self.setup_logging()

    def setup_logging(self):
        """Enhanced logging setup"""
        # Create logs directory if it doesn't exist
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

    def get_service_name(self, port: int) -> str:
        """Get service name for given port"""
        return self.service_names.get(port, 'unknown')

    def extract_version(self, banner: str) -> Optional[str]:
        """Extract version information from banner"""
        if not banner:
            return None

        # Common version patterns
        version_patterns = [
            r'(\d+\.\d+\.?\d*)',  # Basic version pattern
            r'version\s+(\d+\.\d+\.?\d*)',
            r'v(\d+\.\d+\.?\d*)',
            r'/(\d+\.\d+\.?\d*)',
        ]

        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def subnet_discovery(self, target_ip, netmask=24):
        """Discover active hosts in subnet using ARP and ping"""
        try:
            network = ipaddress.IPv4Network(
                f"{target_ip}/{netmask}", strict=False)
            active_hosts = []

            self.logger.info(f"Discovering hosts in subnet: {network}")

            # ARP scan for local network
            if netmask >= 16:  # Only for reasonable subnet sizes
                try:
                    arp_request = ARP(pdst=str(network))
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    arp_request_broadcast = broadcast / arp_request
                    answered_list = srp(
                        arp_request_broadcast, timeout=2, verbose=False)[0]

                    for element in answered_list:
                        host_info = {
                            "ip": element[1].psrc,
                            "mac": element[1].hwsrc,
                            "method": "ARP"
                        }
                        active_hosts.append(host_info)

                except Exception as e:
                    self.logger.warning(f"ARP scan failed: {e}")

            # Ping sweep for broader discovery
            def ping_host_subnet(ip):
                try:
                    if os.name == 'nt':
                        result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(ip)],
                                                capture_output=True, timeout=3)
                    else:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)],
                                                capture_output=True, timeout=3)

                    if result.returncode == 0:
                        return {"ip": str(ip), "mac": None, "method": "PING"}
                except BaseException:
                    pass
                return None

            # Limit ping sweep to reasonable size
            ping_targets = list(
                network.hosts()) if network.num_addresses <= 256 else random.sample(
                list(
                    network.hosts()), 100)

            with ThreadPoolExecutor(max_workers=50) as executor:
                ping_results = list(
                    executor.map(
                        ping_host_subnet,
                        ping_targets))

            for result in ping_results:
                if result and not any(h["ip"] == result["ip"]
                                      for h in active_hosts):
                    active_hosts.append(result)

            self.logger.info(
                f"[+] Found {len(active_hosts)} active hosts in subnet")
            return active_hosts

        except Exception as e:
            self.logger.error(f"Subnet discovery failed: {e}")
            return []

    def port_scan(self, host: str, scan_type: str = "syn",
                  ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """port scanning with multiple techniques"""
        if not ports:
            ports = self.common_ports

        open_ports = []

        try:
            if scan_type == "syn" and not self.stealth_mode:
                # SYN scan using scapy
                self.logger.info(f"Performing SYN scan on {host}")

                def syn_scan_port(port):
                    try:
                        response = sr1(
                            IP(dst=host) / TCP(dport=port, flags="S"),
                            timeout=2, verbose=False
                        )
                        if response and response.haslayer(TCP):
                            if response[TCP].flags == 18:  # SYN-ACK
                                # Send RST to clean up
                                send(IP(dst=host) /
                                     TCP(dport=port, flags="R"), verbose=False)
                                return port
                    except Exception as e:
                        self.logger.debug(
                            f"SYN scan error for port {port}: {e}")
                    return None

                with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    results = executor.map(syn_scan_port, ports)
                    open_ports = [port for port in results if port is not None]

            elif scan_type == "udp":
                # UDP scan
                self.logger.info(f"Performing UDP scan on {host}")

                def udp_scan_port(port):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(2)
                        sock.sendto(b"", (host, port))
                        sock.close()
                        return port  # If no error, port might be open
                    except BaseException:
                        return None

                # UDP scan is slower, use fewer threads
                with ThreadPoolExecutor(max_workers=20) as executor:
                    results = executor.map(
                        udp_scan_port, ports[:50])  # Limit UDP scan
                    open_ports = [port for port in results if port is not None]

            else:
                # Default TCP connect scan
                open_ports = self.tcp_connect_scan(host, ports)

        except Exception as e:
            self.logger.error(f"port scan failed: {e}")
            # Fallback to basic scan
            open_ports = self.tcp_connect_scan(host, ports)

        return open_ports

    def tcp_connect_scan(
            self, host: str, ports: List[int]) -> List[Dict[str, Any]]:
        """Traditional TCP connect scan"""
        open_ports = []

        def scan_port(port):
            try:
                time.sleep(self.rate_limit)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0:
                    service_info = self.enhanced_service_detection(host, port)
                    return {
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        **service_info
                    }
            except Exception as e:
                self.logger.debug(f"TCP scan error for port {port}: {e}")
            return None

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Fix: Use list() to ensure proper type conversion
            results = list(executor.map(scan_port, ports))
            open_ports = [result for result in results if result is not None]

        return open_ports

    def enhanced_service_detection(
            self, host: str, port: int) -> Dict[str, Any]:
        """service detection with vulnerability checks"""
        service_info = {
            "service": "unknown",
            "version": None,
            "banner": None,
            "vulnerabilities": [],
            "ssl_info": None,
            "http_info": None
        }

        try:
            # Basic service identification
            service_info["service"] = self.get_service_name(port)

            # Banner grabbing
            banner = self.grab_banner(host, port)
            if banner:
                service_info["banner"] = banner[:500]
                service_info["version"] = self.extract_version(banner)

                # Check for known vulnerabilities
                service_info["vulnerabilities"] = self.check_vulnerabilities(
                    service_info["service"], banner)

            # SSL/TLS analysis
            if port in [443, 993, 995, 465, 587, 8443]:
                service_info["ssl_info"] = self.analyze_ssl(host, port)

            # HTTP analysis
            if port in [80, 443, 8080, 8443, 8000, 9090]:
                service_info["http_info"] = self.analyze_http(host, port)

        except Exception as e:
            self.logger.debug(
                f"Service detection error for {host}:{port}: {e}")

        return service_info

    def grab_banner(self, host: str, port: int) -> Optional[str]:
        """Enhanced banner grabbing with protocol-specific probes"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))

            # Send protocol-specific probes
            if port == 80:
                sock.send(
                    b"GET / HTTP/1.1\r\nHost: " +
                    host.encode() +
                    b"\r\n\r\n")
            elif port == 25:
                sock.send(b"EHLO test\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            else:
                sock.send(b"\r\n")

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner

        except Exception as e:
            self.logger.debug(f"Banner grab failed for {host}:{port}: {e}")
            return None

    def analyze_ssl(self, host: str, port: int) -> Dict[str, Any]:
        """Comprehensive SSL/TLS analysis"""
        ssl_info = {
            "supported_versions": [],
            "cipher_suites": [],
            "certificate": None,
            "vulnerabilities": []
        }

        try:
            # Get certificate information
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        # Fix: Handle potential missing keys and nested tuples
                        subject_dict = {}
                        issuer_dict = {}

                        for item in cert.get('subject', []):
                            if isinstance(item, (list, tuple)
                                          ) and len(item) > 0:
                                if isinstance(item[0], (list, tuple)) and len(
                                        item[0]) >= 2:
                                    subject_dict[item[0][0]] = item[0][1]

                        for item in cert.get('issuer', []):
                            if isinstance(item, (list, tuple)
                                          ) and len(item) > 0:
                                if isinstance(item[0], (list, tuple)) and len(
                                        item[0]) >= 2:
                                    issuer_dict[item[0][0]] = item[0][1]

                        ssl_info["certificate"] = {
                            "subject": subject_dict,
                            "issuer": issuer_dict,
                            "version": cert.get('version'),
                            "serial_number": cert.get('serialNumber'),
                            "not_before": cert.get('notBefore'),
                            "not_after": cert.get('notAfter'),
                            "signature_algorithm": cert.get('signatureAlgorithm')
                        }

                    # Check for weak protocols
                    protocol_version = ssock.version()
                    if protocol_version and protocol_version in [
                            'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        ssl_info["vulnerabilities"].append(
                            f"Weak protocol: {protocol_version}")

                    ssl_info["protocol_version"] = protocol_version
                    ssl_info["cipher_suite"] = ssock.cipher()

        except Exception as e:
            self.logger.debug(f"SSL analysis failed for {host}:{port}: {e}")

        return ssl_info

    def analyze_http(self, host: str, port: int) -> Dict[str, Any]:
        """HTTP service analysis"""
        http_info = {
            "status_code": None,
            "server": None,
            "title": None,
            "headers": {},
            "technologies": [],
            "directories": []
        }

        try:
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{host}:{port}"

            response = requests.get(
                url, timeout=10, verify=True, allow_redirects=False)

            http_info["status_code"] = response.status_code
            http_info["headers"] = dict(response.headers)
            http_info["server"] = response.headers.get('Server', 'Unknown')

            # Extract page title
            if 'text/html' in response.headers.get('content-type', ''):
                title_match = re.search(
                    r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                if title_match:
                    http_info["title"] = title_match.group(1).strip()

            # Technology detection
            http_info["technologies"] = self.detect_web_technologies(response)

            # Basic directory enumeration
            if not self.stealth_mode:
                http_info["directories"] = self.enumerate_directories(url)

        except Exception as e:
            self.logger.debug(f"HTTP analysis failed for {host}:{port}: {e}")

        return http_info

    def detect_web_technologies(self, response) -> List[str]:
        """Detect web technologies from HTTP response"""
        technologies = []

        # Check headers
        server = response.headers.get('Server', '').lower()
        if 'apache' in server:
            apache_match = re.search(r'apache/([0-9.]+)', server)
            version = apache_match.group(1) if apache_match else ''
            technologies.append(f"Apache {version}".strip())
        if 'nginx' in server:
            nginx_match = re.search(r'nginx/([0-9.]+)', server)
            version = nginx_match.group(1) if nginx_match else ''
            technologies.append(f"Nginx {version}".strip())
        if 'iis' in server:
            technologies.append("Microsoft IIS")

        # Check other headers
        if 'X-Powered-By' in response.headers:
            technologies.append(
                f"Powered by: {
                    response.headers['X-Powered-By']}")

        # Check content
        content = response.text.lower()
        if 'wordpress' in content:
            technologies.append("WordPress")
        if 'drupal' in content:
            technologies.append("Drupal")
        if 'joomla' in content:
            technologies.append("Joomla")

        return technologies

    def enumerate_directories(self, base_url: str) -> List[Dict[str, Any]]:
        common_dirs = [
            'admin', 'login', 'wp-admin', 'administrator', 'panel',
            'config', 'backup', 'test', 'dev', 'staging', 'api',
            'uploads', 'images', 'css', 'js', 'assets', 'files'
        ]

        found_dirs = []

        # Limit to avoid being too aggressive
        for directory in common_dirs[:10]:
            try:
                url = urljoin(base_url, directory)
                response = requests.head(
                    url, timeout=3, verify=False, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    found_dirs.append({
                        "directory": directory,
                        "status_code": response.status_code,
                        "url": url
                    })
            except BaseException:
                continue

        return found_dirs

    def check_vulnerabilities(
            self, service: str, banner: str) -> List[Dict[str, Any]]:
        """Check for known vulnerabilities based on service and banner"""
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


    def dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """Comprehensive DNS enumeration"""
        dns_info = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
            "soa_record": None,
            "subdomains": []
        }

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5

            # A records
            try:
                answers = resolver.resolve(domain, 'A')
                dns_info["a_records"] = [str(rdata) for rdata in answers]
            except BaseException:
                pass

            # AAAA records (IPv6)
            try:
                answers = resolver.resolve(domain, 'AAAA')
                dns_info["aaaa_records"] = [str(rdata) for rdata in answers]
            except BaseException:
                pass

            # MX records - FIXED VERSION
            try:
                answers = resolver.resolve(domain, 'MX')
                mx_records = []
                for rdata in answers:
                    try:
                        # Method 1: Try to access preference and exchange
                        # attributes
                        preference = getattr(rdata, 'preference', 0)
                        exchange = getattr(rdata, 'exchange', str(rdata))
                        mx_records.append(f"{preference} {exchange}")
                    except:
                        # Fallback to string representation
                        mx_records.append(str(rdata))
                dns_info["mx_records"] = mx_records
            except Exception as e:
                self.logger.debug(f"MX record enumeration failed: {e}")
                pass

            # NS records
            try:
                answers = resolver.resolve(domain, 'NS')
                dns_info["ns_records"] = [str(rdata) for rdata in answers]
            except BaseException:
                pass

            # TXT records
            try:
                answers = resolver.resolve(domain, 'TXT')
                dns_info["txt_records"] = [str(rdata) for rdata in answers]
            except BaseException:
                pass

            # SOA record
            try:
                answers = resolver.resolve(domain, 'SOA')
                dns_info["soa_record"] = str(answers[0])
            except BaseException:
                pass

            # Subdomain enumeration
            dns_info["subdomains"] = self.enumerate_subdomains(domain)

        except Exception as e:
            self.logger.error(f"DNS enumeration failed: {e}")

        return dns_info

    def enumerate_subdomains(self, domain: str) -> List[str]:
        """Subdomain enumeration using common prefixes"""
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
            except BaseException:
                continue

        return found_subdomains

    def whois_lookup(self, target: str) -> Dict[str, Any]:
        """WHOIS information gathering"""
        whois_info = {}

        try:
            if self.is_ip_address(target):
                whois_info = {"type": "ip",
                              "info": "IP WHOIS lookup not implemented"}
            else:
                w = whois.whois(target)
                whois_info = {
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
            whois_info = {"error": str(e)}

        return whois_info

    def is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except BaseException:
            return False

    def nmap_integration(
            self, target: str, scan_type: str = "default") -> Dict[str, Any]:
        """Integrate with Nmap for scanning"""
        nmap_results = {}

        try:
            nm = nmap.PortScanner()

            if scan_type == "intense":
                scan_args = '-sS -sV -O -A --script vuln'
            elif scan_type == "stealth":
                scan_args = '-sS -f -D RND:10'
            else:
                scan_args = '-sS -sV'

            nm.scan(target, arguments=scan_args)

            for host in nm.all_hosts():
                nmap_results[host] = {
                    "state": nm[host].state(),
                    "protocols": {},
                    "os": nm[host].get('osmatch', []),
                    "scripts": {}
                }

                for protocol in nm[host].all_protocols():
                    ports = nm[host][protocol].keys()
                    nmap_results[host]["protocols"][protocol] = {}

                    for port in ports:
                        port_info = nm[host][protocol][port]
                        nmap_results[host]["protocols"][protocol][port] = {
                            "state": port_info['state'],
                            "name": port_info['name'],
                            "product": port_info.get('product', ''),
                            "version": port_info.get('version', ''),
                            "extrainfo": port_info.get('extrainfo', ''),
                            "script": port_info.get('script', {})
                        }

        except Exception as e:
            self.logger.error(f"Nmap integration failed: {e}")
            nmap_results = {"error": str(e)}

        return nmap_results

    def comprehensive_scan(self, target, scan_options):
        """Main comprehensive scanning function"""
        start_time = datetime.now()

        results = {
            "scan_info": {
                "target": target,
                "timestamp": start_time.isoformat(),
                "scanner": "Discovery.py",
                "options": scan_options
            },
            "target_info": {},
            "host_discovery": {},
            "port_scan": {},
            "services": [],
            "vulnerabilities": [],
            "ssl_analysis": {},
            "http_analysis": {},
            "dns_enumeration": {},
            "whois_info": {},
            "nmap_results": {},
            "scan_statistics": {}
        }

        try:
            self.logger.info(f"[*] Starting comprehensive scan of {target}")

            # Target resolution and info
            if self.is_ip_address(target):
                results["target_info"]["ip"] = target
                results["target_info"]["type"] = "ip"
            else:
                try:
                    ip = socket.gethostbyname(target)
                    results["target_info"]["ip"] = ip
                    results["target_info"]["hostname"] = target
                    results["target_info"]["type"] = "hostname"
                except BaseException:
                    results["target_info"]["error"] = "Could not resolve hostname"
                    return results

            target_ip = results["target_info"]["ip"]

            # Host discovery
            if scan_options.get("subnet_discovery"):
                self.logger.info("[*] Performing subnet discovery...")
                results["host_discovery"] = self.subnet_discovery(target_ip)

            # Port scanning
            self.logger.info("[*] Performing port scan...")
            scan_type = scan_options.get("scan_type", "tcp")
            port_range = scan_options.get("port_range", "common")

            if port_range == "common":
                ports = self.common_ports
            elif port_range == "top1000":
                ports = self.top_1000_ports
            elif port_range == "all":
                ports = self.all_ports
            else:
                ports = self.common_ports

            open_ports = self.port_scan(target_ip, scan_type, ports)
            results["port_scan"] = {
                "method": scan_type,
                "ports_scanned": len(ports),
                "open_ports": len(open_ports),
                "results": open_ports
            }
            results["services"] = open_ports

            # Vulnerability assessment
            self.logger.info("[*] Analyzing vulnerabilities...")
            all_vulns = []
            for service in open_ports:
                if service.get("vulnerabilities"):
                    all_vulns.extend(service["vulnerabilities"])
            results["vulnerabilities"] = all_vulns

            # DNS enumeration (for hostnames)
            if results["target_info"]["type"] == "hostname":
                self.logger.info("[*] Performing DNS enumeration...")
                results["dns_enumeration"] = self.dns_enumeration(target)

            # WHOIS lookup
            if scan_options.get("whois_lookup"):
                self.logger.info("[*] Performing WHOIS lookup...")
                results["whois_info"] = self.whois_lookup(target)

            # Nmap integration
            if scan_options.get("nmap_scan"):
                self.logger.info("[*] Running Nmap integration...")
                results["nmap_results"] = self.nmap_integration(
                    target_ip, scan_options.get("nmap_type", "default"))

            # Scan statistics
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            results["scan_statistics"] = {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": round(duration, 2),
                "total_ports_scanned": len(ports),
                "open_ports_found": len(open_ports),
                "vulnerabilities_found": len(all_vulns),
                "success_rate": round((len(open_ports) / len(ports)) * 100, 2) if ports else 0
            }

            self.logger.info(f"[+] Scan completed in {duration:.2f} seconds")
            self.logger.info(f"[+] Found {len(open_ports)} open ports")
            self.logger.warning(
                f"[+] Identified {len(all_vulns)} potential vulnerabilities")

        except Exception as e:
            self.logger.error(f"Comprehensive scan failed: {e}")
            results["error"] = str(e)

        return results


def print_detailed_results(results):
    """Print detailed scan results"""
    print("\n" + "=" * 100)
    print("DISCOVERY RESULTS")
    print("=" * 100)

    # Target information
    target_info = results.get("target_info", {})
    print(
        f"\nTarget: {
            target_info.get(
                'hostname',
                target_info.get(
                    'ip',
                    'Unknown'))}")
    print(f"IP Address: {target_info.get('ip', 'Unknown')}")
    print(f"Type: {target_info.get('type', 'Unknown')}")

    # Host discovery
    if results.get("host_discovery"):
        print(f"\nSubnet Hosts Found: {len(results['host_discovery'])}")
        for host in results["host_discovery"][:5]:  # Show first 5
            print(f"  {host['ip']} ({host['method']})" +
                  (f" - {host['mac']}" if host.get('mac') else ""))

    # Port scan results
    port_scan = results.get("port_scan", {})
    print(f"\nPort Scan Results:")
    print(f"  Method: {port_scan.get('method', 'Unknown')}")
    print(f"  Ports Scanned: {port_scan.get('ports_scanned', 0)}")
    print(f"  Open Ports: {port_scan.get('open_ports', 0)}")

    # Services
    if results.get("services"):
        print(f"\nOpen Services:")
        for service in results["services"][:10]:
            port_info = f"{service['port']}/{service.get('protocol', 'tcp')}"
            service_name = service.get('service', 'unknown')
            version = f" ({service['version']})" if service.get(
                'version') else ""
            print(f"  {port_info} - {service_name}{version}")

            if service.get('vulnerabilities'):
                # Show first 2 vulns per service
                for vuln in service['vulnerabilities'][:2]:
                    print(
                        f"    ⚠ {
                            vuln.get(
                                'type',
                                'Unknown')}: {
                            vuln.get(
                                'description',
                                'No description')}")

    # Vulnerabilities summary
    if results.get("vulnerabilities"):
        print(f"\nVulnerability Summary:")
        high_vulns = [v for v in results["vulnerabilities"]
                      if v.get('severity') == 'High']
        medium_vulns = [v for v in results["vulnerabilities"]
                        if v.get('severity') == 'Medium']
        print(f"  High Severity: {len(high_vulns)}")
        print(f"  Medium Severity: {len(medium_vulns)}")
        print(f"  Total: {len(results['vulnerabilities'])}")

    # DNS enumeration
    if results.get("dns_enumeration"):
        dns_info = results["dns_enumeration"]
        print(f"\nDNS Information:")
        if dns_info.get("a_records"):
            print(f"  A Records: {', '.join(dns_info['a_records'])}")
        if dns_info.get("mx_records"):
            print(f"  MX Records: {', '.join(dns_info['mx_records'])}")
        if dns_info.get("subdomains"):
            print(f"  Subdomains Found: {len(dns_info['subdomains'])}")
            for subdomain in dns_info["subdomains"][:5]:
                print(f"    {subdomain}")

    # WHOIS information
    if results.get("whois_info") and not results["whois_info"].get("error"):
        whois_info = results["whois_info"]
        print(f"\nWHOIS Information:")
        if whois_info.get("registrar"):
            print(f"  Registrar: {whois_info['registrar']}")
        if whois_info.get("creation_date"):
            print(f"  Created: {whois_info['creation_date']}")
        if whois_info.get("expiration_date"):
            print(f"  Expires: {whois_info['expiration_date']}")

    # Scan statistics
    stats = results.get("scan_statistics", {})
    print(f"\nScan Statistics:")
    print(f"  Duration: {stats.get('duration_seconds', 0)} seconds")
    print(f"  Success Rate: {stats.get('success_rate', 0)}%")
    print(f"  Vulnerabilities Found: {stats.get('vulnerabilities_found', 0)}")


def save_detailed_results(results, filename=None):
    """Save comprehensive results to JSON file"""
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = results.get(
            "target_info",
            {}).get("hostname") or results.get(
            "target_info",
            {}).get(
            "ip",
            "unknown")
        filename = f"reports/Discovery_{target}_{timestamp}.json"

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        print(f"[+] Detailed results saved to: {filename}")
        return filename
    except Exception as e:
        print(f"[-] Failed to save results: {e}")
        return None


def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Discovery Tool")
    parser.add_argument(
        "target",
        help="Target IP address, hostname, or subnet")
    args = parser.parse_args()

    target = args.target.strip()
    os.makedirs('logs', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    # Max-level scan options
    scan_options = {
        "scan_type": "tcp",        # or "syn" if stealth is preferred
        "port_range": "top1000",
        "subnet_discovery": True,
        "whois_lookup": True,
        "nmap_scan": True,
        "nmap_type": "intense",    # or "stealth" if you want
        "stealth_mode": True
    }

    scanner = Discovery(
        timeout=5,          # You can increase timeout for more thorough scans
        max_threads=200,    # Increase threads for faster scanning
        stealth_mode=True
    )

    print("Discovery Tool")
    print("=" * 60)
    print(f"Target: {target}")
    print("=" * 60)

    try:
        results = scanner.comprehensive_scan(target, scan_options)
        print_detailed_results(results)
        json_file = save_detailed_results(results)
        print(f"\n[+] Scan completed successfully!")
        if json_file:
            print(f"[+] JSON results saved to: {json_file}")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Check for required dependencies
    required_modules = ['scapy', 'dns', 'requests', 'nmap', 'whois']
    missing_modules = []

    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)

    if missing_modules:
        print("Error: Missing required dependencies!")
        print("Please install the following modules:")
        for module in missing_modules:
            print(f"  pip install {module}")
        print("\nFor python-nmap: pip install python-nmap")
        print("For dnspython: pip install dnspython")
        print("For python-whois: pip install python-whois")
        sys.exit(1)

    main()