#!/usr/bin/env python3
"""
Enhanced Enumeration Scanner Module
Intelligently uses discovery reports and provides comprehensive enumeration
"""
import json
import sys
import os
import socket
import subprocess
import platform
import re
import glob
import threading
import time
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional, Tuple

# Import discovery scanner
try:
    from discovery import DiscoveryScanner
except ImportError:
    print("[Error] discovery.py module not found. Please ensure it's in the same directory.")
    sys.exit(1)


class EnhancedEnumerationScanner:
    def __init__(self, target: str, discovery_data: Optional[Dict] = None):
        self.target = target
        self.discovery_data = discovery_data or {}
        self.results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'discovery_summary': {},
            'detailed_enumeration': {
                'banners': {},
                'services': {},
                'versions': {},
                'vulnerabilities': {},
                'web_services': {},
                'database_services': {},
                'network_services': {},
                'security_issues': []
            },
            'os_fingerprint': {},
            'recommendations': [],
            'scan_statistics': {}
        }
        
        # Service categorization
        self.service_categories = {
            'web': [80, 443, 8080, 8443, 3000, 5000, 8000, 9000],
            'database': [3306, 5432, 1433, 27017, 6379, 11211, 9042],
            'remote_access': [22, 23, 3389, 5900, 5901],
            'email': [25, 110, 143, 465, 587, 993, 995],
            'file_transfer': [21, 69, 115, 2049],
            'network_services': [53, 67, 68, 123, 161, 162, 514, 520],
            'security_critical': [135, 139, 445, 1433, 3389, 5985, 5986]
        }
        
        # Enhanced service detection patterns
        self.service_patterns = {
            'apache': {'patterns': [r'apache[/\s]([0-9.]+)', r'server:\s*apache'], 'type': 'web'},
            'nginx': {'patterns': [r'nginx[/\s]([0-9.]+)', r'server:\s*nginx'], 'type': 'web'},
            'iis': {'patterns': [r'microsoft-iis[/\s]([0-9.]+)', r'server:\s*microsoft-iis'], 'type': 'web'},
            'openssh': {'patterns': [r'openssh[_\s]([0-9.]+)', r'ssh-[0-9.]+-openssh'], 'type': 'ssh'},
            'mysql': {'patterns': [r'mysql[/\s]([0-9.]+)', r'[0-9.]+.*mysql'], 'type': 'database'},
            'postgresql': {'patterns': [r'postgresql[/\s]([0-9.]+)', r'postgres'], 'type': 'database'},
            'mongodb': {'patterns': [r'mongodb[/\s]([0-9.]+)', r'mongo'], 'type': 'database'},
            'redis': {'patterns': [r'redis[/\s]([0-9.]+)', r'redis_version'], 'type': 'database'},
            'vsftpd': {'patterns': [r'vsftpd[/\s]([0-9.]+)', r'\(vsftpd'], 'type': 'ftp'},
            'filezilla': {'patterns': [r'filezilla[/\s]([0-9.]+)', r'filezilla'], 'type': 'ftp'},
            'postfix': {'patterns': [r'postfix', r'esmtp postfix'], 'type': 'smtp'},
            'sendmail': {'patterns': [r'sendmail[/\s]([0-9.]+)', r'sendmail'], 'type': 'smtp'},
            'bind': {'patterns': [r'bind[/\s]([0-9.]+)', r'named'], 'type': 'dns'},
            'tomcat': {'patterns': [r'tomcat[/\s]([0-9.]+)', r'apache-coyote'], 'type': 'web'},
            'jetty': {'patterns': [r'jetty[/\s]([0-9.]+)', r'jetty'], 'type': 'web'}
        }
        
        # Vulnerability signatures
        self.vulnerability_patterns = {
            'outdated_ssh': {
                'patterns': [r'openssh[_\s]([4-6]\.[0-9]+)', r'ssh-[12]\.'],
                'severity': 'High',
                'description': 'Outdated SSH version with known vulnerabilities'
            },
            'weak_ssl': {
                'patterns': [r'sslv[23]', r'ssl[_\s]?v?[23]'],
                'severity': 'High', 
                'description': 'Weak SSL/TLS version enabled'
            },
            'default_credentials': {
                'patterns': [r'admin:admin', r'root:root', r'admin:password'],
                'severity': 'Critical',
                'description': 'Default credentials detected'
            },
            'vulnerable_apache': {
                'patterns': [r'apache[/\s](2\.[0-2]\.[0-9]+)'],
                'severity': 'Medium',
                'description': 'Potentially vulnerable Apache version'
            },
            'vulnerable_nginx': {
                'patterns': [r'nginx[/\s](1\.[0-9]\.[0-9]+)'],
                'severity': 'Medium',
                'description': 'Check for nginx vulnerabilities'
            }
        }
        
    def run(self) -> Dict[str, Any]:
        """Execute comprehensive enumeration scan"""
        start_time = datetime.now()
        print(f"[Enumeration] Starting enhanced scan for {self.target}")
        print("=" * 60)
        
        try:
            # Process discovery data
            self._process_discovery_data()
            
            # Detailed service enumeration
            self._detailed_service_enumeration()
            
            # OS fingerprinting
            self._enhanced_os_fingerprinting()
            
            # Security assessment
            self._security_assessment()
            
            # Generate recommendations
            self._generate_recommendations()
            
            # Calculate statistics
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            self.results['scan_statistics'] = {
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': round(duration, 2),
                'services_enumerated': len(self.results['detailed_enumeration']['services']),
                'banners_grabbed': len(self.results['detailed_enumeration']['banners']),
                'vulnerabilities_found': len(self.results['detailed_enumeration']['vulnerabilities']),
                'security_issues': len(self.results['detailed_enumeration']['security_issues'])
            }
            
            # Save results
            self._save_results()
            
            print(f"\n[Enumeration] Scan completed in {duration:.2f} seconds")
            self._print_summary()
            
        except Exception as e:
            print(f"[Enumeration] Scan failed: {e}")
            self.results['error'] = str(e)
            
        return self.results
    
    def _process_discovery_data(self):
        """Process and summarize discovery data"""
        if not self.discovery_data:
            print("[Enumeration] No discovery data provided")
            return
            
        print("[Enumeration] Processing discovery data...")
        
        # Extract summary information
        live_hosts = self.discovery_data.get('live_hosts', [])
        open_ports = self.discovery_data.get('open_ports', [])
        services = self.discovery_data.get('services', [])
        
        self.results['discovery_summary'] = {
            'live_hosts_count': len(live_hosts),
            'open_ports_count': len(open_ports),
            'services_count': len(services),
            'scan_methods_used': []
        }
        
        # Extract detection methods
        for host in live_hosts:
            methods = host.get('detection_methods', [])
            self.results['discovery_summary']['scan_methods_used'].extend(methods)
        
        self.results['discovery_summary']['scan_methods_used'] = list(set(
            self.results['discovery_summary']['scan_methods_used']
        ))
        
        print(f"[Enumeration] Found {len(live_hosts)} live hosts with {len(open_ports)} open ports")
    
    def _detailed_service_enumeration(self):
        """Perform detailed enumeration of discovered services"""
        if not self.discovery_data:
            return
            
        open_ports = self.discovery_data.get('open_ports', [])
        if not open_ports:
            print("[Enumeration] No open ports found in discovery data")
            return
            
        print(f"[Enumeration] Performing detailed enumeration on {len(open_ports)} ports...")
        
        # Group ports by host for efficiency
        ports_by_host = {}
        for port_info in open_ports:
            if isinstance(port_info, dict):
                host = port_info.get('ip', self.target)
                port = port_info.get('port')
                protocol = port_info.get('protocol', 'tcp')
                
                if host not in ports_by_host:
                    ports_by_host[host] = []
                ports_by_host[host].append({
                    'port': port,
                    'protocol': protocol,
                    'service': port_info.get('service', 'unknown'),
                    'state': port_info.get('state', 'open')
                })
        
        # Enumerate each host
        for host, ports in ports_by_host.items():
            print(f"[Enumeration] Enumerating {len(ports)} ports on {host}")
            self._enumerate_host_services(host, ports)
    
    def _enumerate_host_services(self, host: str, ports: List[Dict]):
        """Enumerate services on a specific host"""
        def enumerate_port(port_info):
            port = port_info['port']
            protocol = port_info['protocol']
            service = port_info['service']
            
            port_key = f"{host}:{port}"
            
            try:
                # Enhanced banner grabbing
                banner_info = self._enhanced_banner_grab(host, port, protocol, service)
                if banner_info:
                    self.results['detailed_enumeration']['banners'][port_key] = banner_info
                
                # Service-specific enumeration
                service_info = self._service_specific_enumeration(host, port, protocol, service, banner_info)
                if service_info:
                    self.results['detailed_enumeration']['services'][port_key] = service_info
                
                # Version detection
                version_info = self._enhanced_version_detection(banner_info, service)
                if version_info:
                    self.results['detailed_enumeration']['versions'][port_key] = version_info
                
                # Vulnerability assessment
                vulns = self._check_service_vulnerabilities(service, banner_info, version_info)
                if vulns:
                    self.results['detailed_enumeration']['vulnerabilities'][port_key] = vulns
                
                print(f"[Enumeration] {host}:{port} ({service}) - enumerated")
                
            except Exception as e:
                print(f"[Enumeration] Error enumerating {host}:{port}: {e}")
        
        # Use threading for faster enumeration
        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(enumerate_port, ports)
    
    def _enhanced_banner_grab(self, host: str, port: int, protocol: str, service: str) -> Optional[Dict]:
        """Enhanced banner grabbing with service-specific probes"""
        if protocol.lower() != 'tcp':
            return None
            
        banner_info = {
            'raw_banner': None,
            'headers': {},
            'response_time': None,
            'connection_info': {}
        }
        
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            # Service-specific probes
            probe_data = self._get_service_probe(port, service)
            if probe_data:
                sock.send(probe_data.encode())
            
            # Receive response
            response = sock.recv(4096).decode('utf-8', errors='ignore').strip()
            response_time = time.time() - start_time
            
            banner_info['raw_banner'] = response
            banner_info['response_time'] = round(response_time, 3)
            
            # Parse HTTP headers if it's a web service
            if port in [80, 443, 8080, 8443] or 'http' in service.lower():
                banner_info['headers'] = self._parse_http_headers(response)
            
            sock.close()
            return banner_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def _get_service_probe(self, port: int, service: str) -> Optional[str]:
        """Get appropriate probe for service"""
        probes = {
            80: "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            443: "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            8080: "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            8443: "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            25: "EHLO test.com\r\n",
            110: "USER test\r\n",
            143: "A001 CAPABILITY\r\n",
            21: "",  # FTP sends banner automatically
            22: "",  # SSH sends banner automatically
        }
        
        probe = probes.get(port, "")
        if probe and '{}' in probe:
            return probe.format(self.target)
        return probe
    
    def _parse_http_headers(self, response: str) -> Dict[str, str]:
        """Parse HTTP headers from response"""
        headers = {}
        lines = response.split('\n')
        
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        
        return headers
    
    def _service_specific_enumeration(self, host: str, port: int, protocol: str, 
                                    service: str, banner_info: Dict) -> Optional[Dict]:
        """Perform service-specific enumeration"""
        service_info = {
            'service_type': service,
            'port': port,
            'protocol': protocol,
            'category': self._categorize_service(port),
            'details': {}
        }
        
        # Web service enumeration
        if port in self.service_categories['web']:
            service_info['details'] = self._enumerate_web_service(host, port, banner_info)
            self.results['detailed_enumeration']['web_services'][f"{host}:{port}"] = service_info['details']
        
        # Database service enumeration
        elif port in self.service_categories['database']:
            service_info['details'] = self._enumerate_database_service(host, port, service, banner_info)
            self.results['detailed_enumeration']['database_services'][f"{host}:{port}"] = service_info['details']
        
        # SSH enumeration
        elif port == 22:
            service_info['details'] = self._enumerate_ssh_service(host, port, banner_info)
        
        # FTP enumeration
        elif port == 21:
            service_info['details'] = self._enumerate_ftp_service(host, port, banner_info)
        
        return service_info
    
    def _categorize_service(self, port: int) -> str:
        """Categorize service by port"""
        for category, ports in self.service_categories.items():
            if port in ports:
                return category
        return 'other'
    
    def _enumerate_web_service(self, host: str, port: int, banner_info: Dict) -> Dict:
        """Enumerate web service details"""
        web_info = {
            'server_type': None,
            'technologies': [],
            'security_headers': {},
            'common_paths': [],
            'ssl_info': {}
        }
        
        # Extract server information
        if banner_info and 'headers' in banner_info:
            headers = banner_info['headers']
            web_info['server_type'] = headers.get('server', 'Unknown')
            
            # Check security headers
            security_headers = ['x-frame-options', 'x-xss-protection', 'x-content-type-options', 
                              'strict-transport-security', 'content-security-policy']
            for header in security_headers:
                if header in headers:
                    web_info['security_headers'][header] = headers[header]
        
        # Check for HTTPS
        if port in [443, 8443]:
            web_info['ssl_info'] = self._check_ssl_info(host, port)
        
        return web_info
    
    def _enumerate_database_service(self, host: str, port: int, service: str, banner_info: Dict) -> Dict:
        """Enumerate database service details"""
        db_info = {
            'database_type': service,
            'version': None,
            'authentication_required': True,
            'default_databases': [],
            'security_notes': []
        }
        
        # Extract version from banner
        if banner_info and 'raw_banner' in banner_info:
            banner = banner_info['raw_banner']
            version = self._extract_version_from_banner(banner)
            if version:
                db_info['version'] = version
        
        # Database-specific checks
        if 'mysql' in service.lower():
            db_info['default_databases'] = ['information_schema', 'mysql', 'performance_schema']
        elif 'postgresql' in service.lower():
            db_info['default_databases'] = ['postgres', 'template0', 'template1']
        elif 'mongodb' in service.lower():
            db_info['default_databases'] = ['admin', 'config', 'local']
        
        return db_info
    
    def _enumerate_ssh_service(self, host: str, port: int, banner_info: Dict) -> Dict:
        """Enumerate SSH service details"""
        ssh_info = {
            'version': None,
            'supported_auth_methods': [],
            'algorithms': {},
            'security_issues': []
        }
        
        if banner_info and 'raw_banner' in banner_info:
            banner = banner_info['raw_banner']
            
            # Extract SSH version
            version_match = re.search(r'SSH-(\d+\.\d+)', banner)
            if version_match:
                ssh_info['version'] = version_match.group(1)
                
                # Check for old SSH versions
                if ssh_info['version'] in ['1.0', '1.5']:
                    ssh_info['security_issues'].append('Deprecated SSH version')
        
        return ssh_info
    
    def _enumerate_ftp_service(self, host: str, port: int, banner_info: Dict) -> Dict:
        """Enumerate FTP service details"""
        ftp_info = {
            'server_type': None,
            'version': None,
            'anonymous_login': False,
            'security_issues': []
        }
        
        if banner_info and 'raw_banner' in banner_info:
            banner = banner_info['raw_banner']
            
            # Check for FTP server type
            if 'vsftpd' in banner.lower():
                ftp_info['server_type'] = 'vsftpd'
            elif 'filezilla' in banner.lower():
                ftp_info['server_type'] = 'filezilla'
            elif 'proftpd' in banner.lower():
                ftp_info['server_type'] = 'proftpd'
            
            # Extract version
            version = self._extract_version_from_banner(banner)
            if version:
                ftp_info['version'] = version
        
        # Test for anonymous login
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login('anonymous', 'anonymous@test.com')
            ftp_info['anonymous_login'] = True
            ftp_info['security_issues'].append('Anonymous FTP access enabled')
            ftp.quit()
        except:
            pass
        
        return ftp_info
    
    def _check_ssl_info(self, host: str, port: int) -> Dict:
        """Check SSL/TLS information"""
        ssl_info = {
            'certificate_info': {},
            'supported_protocols': [],
            'cipher_suites': [],
            'security_issues': []
        }
        
        try:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        ssl_info['certificate_info'] = {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'serial_number': cert.get('serialNumber')
                        }
                    
                    # Check protocol version
                    protocol = ssock.version()
                    if protocol:
                        ssl_info['supported_protocols'].append(protocol)
                        
                        # Check for weak protocols
                        if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                            ssl_info['security_issues'].append(f'Weak protocol {protocol} supported')
        
        except Exception as e:
            ssl_info['error'] = str(e)
        
        return ssl_info
    
    def _enhanced_version_detection(self, banner_info: Dict, service: str) -> Optional[Dict]:
        """Enhanced version detection using multiple methods"""
        version_info = {
            'detected_versions': [],
            'confidence': 'low',
            'detection_method': []
        }
        
        if not banner_info or 'raw_banner' not in banner_info:
            return None
        
        banner = banner_info['raw_banner']
        
        # Service-specific version detection
        for service_name, patterns_info in self.service_patterns.items():
            if service_name.lower() in service.lower() or service_name.lower() in banner.lower():
                for pattern in patterns_info['patterns']:
                    match = re.search(pattern, banner, re.IGNORECASE)
                    if match:
                        if match.groups():
                            version_info['detected_versions'].append(match.group(1))
                        else:
                            version_info['detected_versions'].append(match.group(0))
                        version_info['detection_method'].append(f'Pattern match: {pattern}')
                        version_info['confidence'] = 'high'
        
        # Generic version patterns
        if not version_info['detected_versions']:
            generic_patterns = [
                r'([0-9]+\.[0-9]+\.[0-9]+)',
                r'([0-9]+\.[0-9]+)',
                r'version\s+([0-9]+\.[0-9]+\.?[0-9]*)',
                r'v([0-9]+\.[0-9]+\.?[0-9]*)',
                r'/([0-9]+\.[0-9]+\.?[0-9]*)'
            ]
            
            for pattern in generic_patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    version_info['detected_versions'].append(match.group(1))
                    version_info['detection_method'].append(f'Generic pattern: {pattern}')
                    version_info['confidence'] = 'medium'
                    break
        
        return version_info if version_info['detected_versions'] else None
    
    def _check_service_vulnerabilities(self, service: str, banner_info: Dict, 
                                     version_info: Dict) -> List[Dict]:
        """Check for service-specific vulnerabilities"""
        vulnerabilities = []
        
        if not banner_info or 'raw_banner' not in banner_info:
            return vulnerabilities
        
        banner = banner_info['raw_banner'].lower()
        
        # Check against vulnerability patterns
        for vuln_name, vuln_info in self.vulnerability_patterns.items():
            for pattern in vuln_info['patterns']:
                if re.search(pattern, banner, re.IGNORECASE):
                    vulnerabilities.append({
                        'name': vuln_name,
                        'severity': vuln_info['severity'],
                        'description': vuln_info['description'],
                        'detected_via': f'Banner pattern: {pattern}'
                    })
        
        # Version-specific vulnerability checks
        if version_info and version_info.get('detected_versions'):
            for version in version_info['detected_versions']:
                version_vulns = self._check_version_vulnerabilities(service, version)
                vulnerabilities.extend(version_vulns)
        
        return vulnerabilities
    
    def _check_version_vulnerabilities(self, service: str, version: str) -> List[Dict]:
        """Check for version-specific vulnerabilities"""
        vulnerabilities = []
        
        # Known vulnerable versions
        vulnerable_versions = {
            'openssh': {
                '7.3': 'CVE-2016-10708 - Information disclosure',
                '6.6': 'CVE-2015-5600 - Keyboard-interactive authentication brute force',
                '5.3': 'CVE-2010-4478 - Weakness in random number generation'
            },
            'apache': {
                '2.2.0': 'Multiple vulnerabilities in Apache 2.2.x series',
                '2.0.0': 'Multiple vulnerabilities in Apache 2.0.x series'
            },
            'nginx': {
                '1.0.0': 'Multiple vulnerabilities in nginx 1.0.x series'
            }
        }
        
        service_lower = service.lower()
        
        for vuln_service, versions in vulnerable_versions.items():
            if vuln_service in service_lower:
                for vuln_version, description in versions.items():
                    if version.startswith(vuln_version):
                        vulnerabilities.append({
                            'name': f'{vuln_service}_version_vulnerability',
                            'severity': 'Medium',
                            'description': description,
                            'version': version,
                            'detected_via': 'Version analysis'
                        })
        
        return vulnerabilities
    
    def _extract_version_from_banner(self, banner: str) -> Optional[str]:
        """Extract version information from banner"""
        if not banner:
            return None
            
        version_patterns = [
            r'([0-9]+\.[0-9]+\.[0-9]+)',
            r'([0-9]+\.[0-9]+)',
            r'version\s+([0-9]+\.[0-9]+\.?[0-9]*)',
            r'v([0-9]+\.[0-9]+\.?[0-9]*)',
            r'/([0-9]+\.[0-9]+\.?[0-9]*)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return None
    
    def _enhanced_os_fingerprinting(self):
        """Enhanced OS fingerprinting using multiple techniques"""
        print("[Enumeration] Performing OS fingerprinting...")
        
        os_info = {
            'ttl_analysis': {},
            'banner_analysis': {},
            'service_analysis': {},
            'final_guess': 'Unknown',
            'confidence': 'Low'
        }
        
        # TTL-based fingerprinting
        ttl_info = self._ttl_fingerprinting()
        if ttl_info:
            os_info['ttl_analysis'] = ttl_info
        
        # Banner-based OS detection
        banner_os = self._banner_os_detection()
        if banner_os:
            os_info['banner_analysis'] = banner_os
        
        # Service-based OS detection
        service_os = self._service_os_detection()
        if service_os:
            os_info['service_analysis'] = service_os
        
        # Combine results for final guess
        os_info['final_guess'], os_info['confidence'] = self._combine_os_results(os_info)
        
        self.results['os_fingerprint'] = os_info
        print(f"[Enumeration] OS fingerprint: {os_info['final_guess']} (confidence: {os_info['confidence']})")
    
    def _ttl_fingerprinting(self) -> Optional[Dict]:
        """TTL-based OS fingerprinting"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', self.target]
            else:
                cmd = ['ping', '-c', '1', self.target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                ttl = self._extract_ttl_from_ping(result.stdout)
                if ttl:
                    return {
                        'ttl': ttl,
                        'os_guess': self._guess_os_from_ttl(ttl),
                        'method': 'TTL Analysis'
                    }
        except:
            pass
        
        return None
    
    def _extract_ttl_from_ping(self, ping_output: str) -> Optional[int]:
        """Extract TTL value from ping output"""
        ttl_patterns = [
            r'ttl=(\d+)',
            r'TTL=(\d+)',
            r'time to live.*?(\d+)',
            r'hop limit.*?(\d+)'
        ]
        
        for pattern in ttl_patterns:
            match = re.search(pattern, ping_output, re.IGNORECASE)
            if match:
                return int(match.group(1))
        
        return None
    
    def _guess_os_from_ttl(self, ttl: int) -> str:
        """Guess OS based on TTL value"""
        ttl_ranges = {
            (60, 65): 'Linux/Unix',
            (120, 129): 'Windows',
            (240, 255): 'Cisco/Network Device',
            (30, 35): 'Windows 95/98',
            (250, 255): 'Solaris/AIX'
        }
        
        
        for (min_ttl, max_ttl), os_type in ttl_ranges.items():
            if min_ttl <= ttl <= max_ttl:
                return os_type
        
        return f'Unknown (TTL: {ttl})'
    
    def _banner_os_detection(self) -> Optional[Dict]:
        """OS detection based on service banners"""
        os_indicators = {
            'windows': ['microsoft', 'windows', 'win32', 'iis'],
            'linux': ['linux', 'ubuntu', 'debian', 'centos', 'redhat', 'apache'],
            'unix': ['unix', 'solaris', 'aix', 'hp-ux', 'freebsd', 'openbsd'],
            'cisco': ['cisco', 'ios'],
            'embedded': ['busybox', 'embedded']
        }
        
        banner_os_info = {
            'detected_systems': [],
            'confidence_scores': {},
            'evidence': []
        }
        
        # Analyze all banners
        for port_key, banner_info in self.results['detailed_enumeration']['banners'].items():
            if not banner_info or 'raw_banner' not in banner_info:
                continue
                
            banner = banner_info['raw_banner'].lower()
            
            for os_type, indicators in os_indicators.items():
                score = 0
                found_indicators = []
                
                for indicator in indicators:
                    if indicator in banner:
                        score += 1
                        found_indicators.append(indicator)
                
                if score > 0:
                    if os_type not in banner_os_info['confidence_scores']:
                        banner_os_info['confidence_scores'][os_type] = 0
                    banner_os_info['confidence_scores'][os_type] += score
                    banner_os_info['evidence'].append({
                        'port': port_key,
                        'os_type': os_type,
                        'indicators': found_indicators,
                        'banner_snippet': banner[:100]
                    })
        
        # Determine most likely OS
        if banner_os_info['confidence_scores']:
            best_os = max(banner_os_info['confidence_scores'], 
                         key=banner_os_info['confidence_scores'].get)
            banner_os_info['detected_systems'] = [best_os]
        
        return banner_os_info if banner_os_info['detected_systems'] else None
    
    def _service_os_detection(self) -> Optional[Dict]:
        """OS detection based on service combinations"""
        service_os_patterns = {
            'windows': {
                'ports': [135, 139, 445, 3389, 1433],
                'services': ['microsoft-ds', 'ms-wbt-server', 'ms-sql']
            },
            'linux': {
                'ports': [22, 80, 443],
                'services': ['ssh', 'http', 'https', 'apache', 'nginx']
            },
            'cisco': {
                'ports': [23, 161, 162],
                'services': ['telnet', 'snmp']
            }
        }
        
        service_scores = {}
        open_ports = self.discovery_data.get('open_ports', [])
        
        if not open_ports:
            return None
        
        # Extract port numbers
        detected_ports = []
        detected_services = []
        
        for port_info in open_ports:
            if isinstance(port_info, dict):
                port = port_info.get('port')
                service = port_info.get('service', '').lower()
                if port:
                    detected_ports.append(port)
                if service:
                    detected_services.append(service)
        
        # Score based on port/service combinations
        for os_type, patterns in service_os_patterns.items():
            score = 0
            
            # Port-based scoring
            for port in patterns['ports']:
                if port in detected_ports:
                    score += 2
            
            # Service-based scoring
            for service in patterns['services']:
                for detected_service in detected_services:
                    if service in detected_service:
                        score += 3
            
            if score > 0:
                service_scores[os_type] = score
        
        if service_scores:
            best_os = max(service_scores, key=service_scores.get)
            return {
                'detected_systems': [best_os],
                'confidence_scores': service_scores,
                'method': 'Service Pattern Analysis'
            }
        
        return None
    
    def _combine_os_results(self, os_info: Dict) -> Tuple[str, str]:
        """Combine OS detection results for final assessment"""
        os_votes = {}
        confidence_weights = {
            'ttl_analysis': 1,
            'banner_analysis': 3,
            'service_analysis': 2
        }
        
        # Collect votes from different methods
        for method, weight in confidence_weights.items():
            if method in os_info and os_info[method]:
                if method == 'ttl_analysis':
                    os_guess = os_info[method].get('os_guess', '')
                    if os_guess and os_guess != 'Unknown':
                        os_type = os_guess.split('/')[0].lower()
                        os_votes[os_type] = os_votes.get(os_type, 0) + weight
                else:
                    detected_systems = os_info[method].get('detected_systems', [])
                    for system in detected_systems:
                        os_votes[system] = os_votes.get(system, 0) + weight
        
        if not os_votes:
            return 'Unknown', 'Low'
        
        # Determine final OS and confidence
        best_os = max(os_votes, key=os_votes.get)
        max_score = os_votes[best_os]
        total_possible = sum(confidence_weights.values())
        
        confidence_ratio = max_score / total_possible
        
        if confidence_ratio >= 0.6:
            confidence = 'High'
        elif confidence_ratio >= 0.3:
            confidence = 'Medium'
        else:
            confidence = 'Low'
        
        return best_os.title(), confidence
    
    def _security_assessment(self):
        """Comprehensive security assessment"""
        print("[Enumeration] Performing security assessment...")
        
        security_issues = []
        
        # Check for common security issues
        security_issues.extend(self._check_weak_services())
        security_issues.extend(self._check_default_credentials())
        security_issues.extend(self._check_ssl_vulnerabilities())
        security_issues.extend(self._check_information_disclosure())
        security_issues.extend(self._check_outdated_services())
        
        self.results['detailed_enumeration']['security_issues'] = security_issues
        print(f"[Enumeration] Found {len(security_issues)} security issues")
    
    def _check_weak_services(self) -> List[Dict]:
        """Check for weak or vulnerable services"""
        weak_services = []
        risky_ports = {
            23: {'service': 'Telnet', 'risk': 'High', 'reason': 'Unencrypted remote access'},
            21: {'service': 'FTP', 'risk': 'Medium', 'reason': 'Potentially unencrypted file transfer'},
            53: {'service': 'DNS', 'risk': 'Medium', 'reason': 'Potential DNS amplification attacks'},
            161: {'service': 'SNMP', 'risk': 'Medium', 'reason': 'Information disclosure via SNMP'},
            135: {'service': 'RPC', 'risk': 'High', 'reason': 'Windows RPC vulnerabilities'},
            445: {'service': 'SMB', 'risk': 'High', 'reason': 'SMB vulnerabilities and lateral movement'}
        }
        
        open_ports = self.discovery_data.get('open_ports', [])
        
        for port_info in open_ports:
            if isinstance(port_info, dict):
                port = port_info.get('port')
                if port in risky_ports:
                    weak_services.append({
                        'type': 'weak_service',
                        'port': port,
                        'service': risky_ports[port]['service'],
                        'severity': risky_ports[port]['risk'],
                        'description': risky_ports[port]['reason'],
                        'recommendation': f'Consider disabling or securing {risky_ports[port]["service"]} service'
                    })
        
        return weak_services
    
    def _check_default_credentials(self) -> List[Dict]:
        """Check for services with potential default credentials"""
        default_cred_issues = []
        
        # Common default credential checks
        credential_tests = {
            22: [('root', 'root'), ('admin', 'admin'), ('root', '')],
            23: [('admin', 'admin'), ('root', 'root'), ('cisco', 'cisco')],
            21: [('anonymous', ''), ('ftp', 'ftp'), ('admin', 'admin')],
            3306: [('root', ''), ('root', 'root'), ('mysql', 'mysql')],
            5432: [('postgres', ''), ('postgres', 'postgres')],
            1433: [('sa', ''), ('sa', 'sa'), ('admin', 'admin')]
        }
        
        open_ports = self.discovery_data.get('open_ports', [])
        
        for port_info in open_ports:
            if isinstance(port_info, dict):
                port = port_info.get('port')
                if port in credential_tests:
                    # Note: In a real implementation, you'd actually test these
                    # Here we just flag the potential issue
                    default_cred_issues.append({
                        'type': 'default_credentials',
                        'port': port,
                        'severity': 'Critical',
                        'description': f'Service on port {port} may have default credentials',
                        'recommendation': 'Test for and change default credentials immediately',
                        'common_credentials': credential_tests[port]
                    })
        
        return default_cred_issues
    
    def _check_ssl_vulnerabilities(self) -> List[Dict]:
        """Check for SSL/TLS vulnerabilities"""
        ssl_issues = []
        
        for port_key, service_info in self.results['detailed_enumeration']['web_services'].items():
            if 'ssl_info' in service_info and service_info['ssl_info']:
                ssl_info = service_info['ssl_info']
                
                # Check for security issues in SSL info
                if 'security_issues' in ssl_info:
                    for issue in ssl_info['security_issues']:
                        ssl_issues.append({
                            'type': 'ssl_vulnerability',
                            'port': port_key,
                            'severity': 'High',
                            'description': issue,
                            'recommendation': 'Update SSL/TLS configuration'
                        })
                
                # Check certificate validity
                if 'certificate_info' in ssl_info and ssl_info['certificate_info']:
                    cert_info = ssl_info['certificate_info']
                    
                    # Check certificate expiration
                    if 'not_after' in cert_info:
                        try:
                            from datetime import datetime
                            not_after = datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (not_after - datetime.now()).days
                            
                            if days_until_expiry < 30:
                                ssl_issues.append({
                                    'type': 'certificate_expiry',
                                    'port': port_key,
                                    'severity': 'Medium',
                                    'description': f'SSL certificate expires in {days_until_expiry} days',
                                    'recommendation': 'Renew SSL certificate before expiration'
                                })
                        except:
                            pass
        
        return ssl_issues
    
    def _check_information_disclosure(self) -> List[Dict]:
        """Check for information disclosure issues"""
        disclosure_issues = []
        
        # Check banners for information disclosure
        for port_key, banner_info in self.results['detailed_enumeration']['banners'].items():
            if not banner_info or 'raw_banner' not in banner_info:
                continue
                
            banner = banner_info['raw_banner']
            
            # Check for verbose banners
            disclosure_patterns = [
                (r'server:\s*apache/([0-9.]+)', 'Web server version disclosure'),
                (r'server:\s*nginx/([0-9.]+)', 'Web server version disclosure'),
                (r'openssh[_\s]([0-9.]+)', 'SSH version disclosure'),
                (r'microsoft-iis/([0-9.]+)', 'IIS version disclosure'),
                (r'version\s+([0-9.]+)', 'Service version disclosure')
            ]
            
            for pattern, description in disclosure_patterns:
                if re.search(pattern, banner, re.IGNORECASE):
                    disclosure_issues.append({
                        'type': 'information_disclosure',
                        'port': port_key,
                        'severity': 'Low',
                        'description': description,
                        'recommendation': 'Configure service to hide version information',
                        'evidence': banner[:100]
                    })
                    break
        
        return disclosure_issues
    
    def _check_outdated_services(self) -> List[Dict]:
        """Check for outdated service versions"""
        outdated_issues = []
        
        # Known outdated versions
        outdated_versions = {
            'apache': ['2.2.', '2.0.'],
            'nginx': ['1.0.', '1.2.'],
            'openssh': ['5.', '6.0', '6.1', '6.2'],
            'mysql': ['5.0', '5.1'],
            'php': ['5.', '7.0', '7.1']
        }
        
        for port_key, version_info in self.results['detailed_enumeration']['versions'].items():
            if not version_info or 'detected_versions' not in version_info:
                continue
                
            for version in version_info['detected_versions']:
                for service, old_versions in outdated_versions.items():
                    service_detected = False
                    
                    # Check if this service was detected for this port
                    if port_key in self.results['detailed_enumeration']['services']:
                        service_info = self.results['detailed_enumeration']['services'][port_key]
                        if service.lower() in service_info.get('service_type', '').lower():
                            service_detected = True
                    
                    if service_detected:
                        for old_version in old_versions:
                            if version.startswith(old_version):
                                outdated_issues.append({
                                    'type': 'outdated_service',
                                    'port': port_key,
                                    'service': service,
                                    'version': version,
                                    'severity': 'Medium',
                                    'description': f'Outdated {service} version {version} detected',
                                    'recommendation': f'Update {service} to the latest stable version'
                                })
                                break
        
        return outdated_issues
    
    def _generate_recommendations(self):
        """Generate security recommendations based on findings"""
        print("[Enumeration] Generating recommendations...")
        
        recommendations = []
        
        # Analyze security issues
        security_issues = self.results['detailed_enumeration']['security_issues']
        
        # Count issues by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for issue in security_issues:
            severity = issue.get('severity', 'Low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Generate priority recommendations
        if severity_counts['Critical'] > 0:
            recommendations.append({
                'priority': 'Critical',
                'category': 'Immediate Action Required',
                'recommendation': f'Address {severity_counts["Critical"]} critical security issues immediately',
                'details': 'Critical issues pose immediate security risks and should be resolved ASAP'
            })
        
        if severity_counts['High'] > 0:
            recommendations.append({
                'priority': 'High',
                'category': 'Security Hardening',
                'recommendation': f'Fix {severity_counts["High"]} high-severity security issues',
                'details': 'High-severity issues should be addressed within 24-48 hours'
            })
        
        # Service-specific recommendations
        open_ports = self.discovery_data.get('open_ports', [])
        
        # Check for unnecessary services
        risky_ports = [21, 23, 135, 139, 445, 161]
        exposed_risky = [p for p in risky_ports if any(
            port_info.get('port') == p for port_info in open_ports if isinstance(port_info, dict)
        )]
        
        if exposed_risky:
            recommendations.append({
                'priority': 'High',
                'category': 'Service Management',
                'recommendation': 'Disable or secure unnecessary services',
                'details': f'Consider disabling services on ports: {", ".join(map(str, exposed_risky))}'
            })
        
        # SSL/TLS recommendations
        ssl_issues = [issue for issue in security_issues if issue.get('type') == 'ssl_vulnerability']
        if ssl_issues:
            recommendations.append({
                'priority': 'High',
                'category': 'Encryption',
                'recommendation': 'Update SSL/TLS configuration',
                'details': 'Disable weak SSL/TLS protocols and enable strong cipher suites'
            })
        
        # Version management
        outdated_services = [issue for issue in security_issues if issue.get('type') == 'outdated_service']
        if outdated_services:
            recommendations.append({
                'priority': 'Medium',
                'category': 'Patch Management',
                'recommendation': 'Update outdated services',
                'details': f'{len(outdated_services)} services need updates for security patches'
            })
        
        # General security recommendations
        recommendations.extend([
            {
                'priority': 'Medium',
                'category': 'Network Security',
                'recommendation': 'Implement network segmentation',
                'details': 'Use firewalls to restrict access to critical services'
            },
            {
                'priority': 'Medium',
                'category': 'Monitoring',
                'recommendation': 'Deploy security monitoring',
                'details': 'Implement logging and monitoring for detected services'
            },
            {
                'priority': 'Low',
                'category': 'Information Security',
                'recommendation': 'Minimize information disclosure',
                'details': 'Configure services to hide version and system information'
            }
        ])
        
        self.results['recommendations'] = recommendations
    
    def _save_results(self):
        """Save enumeration results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"output/enumeration_results_{self.target.replace('.', '_')}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"[Enumeration] Results saved to {filename}")
            
            # Also save a summary text file
            summary_filename = f"output/enumeration_summary_{self.target.replace('.', '_')}_{timestamp}.txt"
            self._save_text_summary(summary_filename)
            
        except Exception as e:
            print(f"[Enumeration] Error saving results: {e}")
    
    def _save_text_summary(self, filename: str):
        """Save a human-readable summary"""
        try:
            with open(filename, 'w') as f:
                f.write("=" * 60 + "\n")
                f.write(f"ENUMERATION REPORT - {self.target}\n")
                f.write(f"Generated: {self.results['scan_time']}\n")
                f.write("=" * 60 + "\n\n")
                
                # Discovery Summary
                if self.results['discovery_summary']:
                    f.write("DISCOVERY SUMMARY:\n")
                    f.write("-" * 20 + "\n")
                    summary = self.results['discovery_summary']
                    f.write(f"Live Hosts: {summary.get('live_hosts_count', 0)}\n")
                    f.write(f"Open Ports: {summary.get('open_ports_count', 0)}\n")
                    f.write(f"Services: {summary.get('services_count', 0)}\n\n")
                
                # OS Fingerprint
                if self.results['os_fingerprint']:
                    f.write("OS FINGERPRINT:\n")
                    f.write("-" * 15 + "\n")
                    os_info = self.results['os_fingerprint']
                    f.write(f"Detected OS: {os_info.get('final_guess', 'Unknown')}\n")
                    f.write(f"Confidence: {os_info.get('confidence', 'Low')}\n\n")
                
                # Security Issues
                security_issues = self.results['detailed_enumeration']['security_issues']
                if security_issues:
                    f.write("SECURITY ISSUES:\n")
                    f.write("-" * 16 + "\n")
                    for issue in security_issues:
                        f.write(f"[{issue.get('severity', 'Unknown')}] {issue.get('description', 'Unknown issue')}\n")
                        if 'recommendation' in issue:
                            f.write(f"  -> {issue['recommendation']}\n")
                        f.write("\n")
                
                # Recommendations
                if self.results['recommendations']:
                    f.write("RECOMMENDATIONS:\n")
                    f.write("-" * 16 + "\n")
                    for rec in self.results['recommendations']:
                        f.write(f"[{rec.get('priority', 'Unknown')}] {rec.get('recommendation', 'Unknown')}\n")
                        f.write(f"  {rec.get('details', '')}\n\n")
                
                # Statistics
                if self.results['scan_statistics']:
                    f.write("SCAN STATISTICS:\n")
                    f.write("-" * 16 + "\n")
                    stats = self.results['scan_statistics']
                    f.write(f"Duration: {stats.get('duration_seconds', 0)} seconds\n")
                    f.write(f"Services Enumerated: {stats.get('services_enumerated', 0)}\n")
                    f.write(f"Banners Grabbed: {stats.get('banners_grabbed', 0)}\n")
                    f.write(f"Vulnerabilities Found: {stats.get('vulnerabilities_found', 0)}\n")
                    f.write(f"Security Issues: {stats.get('security_issues', 0)}\n")
                
            print(f"[Enumeration] Summary saved to {filename}")
            
        except Exception as e:
            print(f"[Enumeration] Error saving summary: {e}")
    
    def _print_summary(self):
        """Print enumeration summary to console"""
        print("\n" + "=" * 60)
        print(f"ENUMERATION SUMMARY - {self.target}")
        print("=" * 60)
        
        # OS Information
        if self.results['os_fingerprint']:
            os_info = self.results['os_fingerprint']
            print(f"Detected OS: {os_info.get('final_guess', 'Unknown')} "
                  f"(Confidence: {os_info.get('confidence', 'Low')})")
        
        # Service Statistics
        stats = self.results['scan_statistics']
        print(f"Services Enumerated: {stats.get('services_enumerated', 0)}")
        print(f"Banners Grabbed: {stats.get('banners_grabbed', 0)}")
        print(f"Vulnerabilities Found: {stats.get('vulnerabilities_found', 0)}")
        
        # Security Issues Summary
        security_issues = self.results['detailed_enumeration']['security_issues']
        if security_issues:
            severity_counts = {}
            for issue in security_issues:
                severity = issue.get('severity', 'Unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            print("\nSecurity Issues by Severity:")
            for severity, count in sorted(severity_counts.items()):
                print(f"  {severity}: {count}")
        
        # Top Recommendations
        if self.results['recommendations']:
            print("\nTop Priority Recommendations:")
            critical_high = [r for r in self.results['recommendations'] 
                           if r.get('priority') in ['Critical', 'High']]
            for rec in critical_high[:3]:
                print(f"  [{rec.get('priority')}] {rec.get('recommendation')}")
        
        print("=" * 60)
    
    def load_discovery_report(self, report_path: str) -> bool:
        """Load existing discovery report"""
        try:
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    self.discovery_data = json.load(f)
                print(f"[Enumeration] Loaded discovery report from {report_path}")
                return True
            else:
                print(f"[Enumeration] Discovery report not found at {report_path}")
                return False
        except Exception as e:
            print(f"[Enumeration] Error loading discovery report: {e}")
            return False
    
    def run_discovery_if_needed(self) -> bool:
        """Run discovery scan if no discovery data is available"""
        if self.discovery_data:
            print("[Enumeration] Using existing discovery data")
            return True
        
        print("[Enumeration] No discovery data found, running discovery scan...")
        
        try:
            # Initialize and run discovery scanner
            discovery_scanner = DiscoveryScanner(self.target)
            discovery_results = discovery_scanner.run()
            
            if discovery_results:
                self.discovery_data = discovery_results
                print("[Enumeration] Discovery scan completed successfully")
                return True
            else:
                print("[Enumeration] Discovery scan failed")
                return False
                
        except Exception as e:
            print(f"[Enumeration] Error running discovery: {e}")
            return False


def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Enumeration Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-d', '--discovery-report', help='Path to existing discovery report')
    parser.add_argument('-o', '--output', help='Output directory for results')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = EnhancedEnumerationScanner(args.target)
    
    # Load discovery report if provided
    if args.discovery_report:
        if not scanner.load_discovery_report(args.discovery_report):
            print("[Error] Failed to load discovery report")
            return
    
    # Run discovery if needed
    if not scanner.run_discovery_if_needed():
        print("[Error] Unable to obtain discovery data")
        return
    
    # Change output directory if specified
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        os.chdir(args.output)
    
    # Run enumeration
    results = scanner.run()
    
    if results.get('error'):
        print(f"[Error] Enumeration failed: {results['error']}")
        sys.exit(1)
    else:
        print("[Success] Enumeration completed successfully")


if __name__ == "__main__":
    main()