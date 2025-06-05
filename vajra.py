#!/usr/bin/env python3
"""
Vajra - Comprehensive Vulnerability Assessment & Compliance Tool
Author: Security Team
Version: 1.0
"""

import sys
import os
import json
import argparse
import asyncio
import time
from datetime import datetime
from pathlib import Path
import subprocess
import logging
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vajra.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VajraScanner:
    """Main orchestrator for Vajra vulnerability assessment tool"""
    
    def __init__(self):
        self.results = {
            'scan_metadata': {
                'start_time': datetime.now().isoformat(),
                'tool_version': '1.0',
                'target': None,
                'scan_duration': None
            },
            'discovery': [],
            'enumeration': [],
            'vulnerabilities': [],
            'deep_scan': [],
            'webapp_findings': [],
            'compliance': [],
            'malware_indicators': []
        }
        
    def run_module(self, module_script: str, args: List[str]) -> Optional[Dict]:
        """Execute a module script and return parsed JSON results"""
        try:
            cmd = ['python3', module_script] + args
            logger.info(f"Running: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Module {module_script} failed: {result.stderr}")
                return None
                
            if result.stdout.strip():
                return json.loads(result.stdout)
            return []
            
        except subprocess.TimeoutExpired:
            logger.error(f"Module {module_script} timed out")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from {module_script}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error running {module_script}: {e}")
            return None

    async def discovery_phase(self, target: str) -> bool:
        """Phase 1: Network discovery and host identification"""
        logger.info("=== DISCOVERY PHASE ===")
        
        if not os.path.exists('discovery.py'):
            logger.error("discovery.py module not found")
            return False
            
        results = self.run_module('discovery.py', [target])
        if results is not None:
            self.results['discovery'] = results
            live_hosts = [h for h in results if h.get('status') == 'up']
            logger.info(f"Found {len(live_hosts)} live hosts")
            return len(live_hosts) > 0
        return False

    async def enumeration_phase(self, target: str) -> bool:
        """Phase 2: Port scanning and service enumeration"""
        logger.info("=== ENUMERATION PHASE ===")
        
        if not os.path.exists('enumeration.py'):
            logger.error("enumeration.py module not found")
            return False
            
        # If we found multiple hosts in discovery, enumerate each
        targets_to_enumerate = []
        if self.results['discovery']:
            targets_to_enumerate = [h['ip'] for h in self.results['discovery'] 
                                  if h.get('status') == 'up']
        else:
            targets_to_enumerate = [target]
            
        all_enumeration_results = []
        for host in targets_to_enumerate:
            results = self.run_module('enumeration.py', [host])
            if results:
                all_enumeration_results.append({
                    'host': host,
                    'ports': results
                })
                
        self.results['enumeration'] = all_enumeration_results
        total_ports = sum(len(h['ports']) for h in all_enumeration_results)
        logger.info(f"Enumerated {total_ports} services across {len(all_enumeration_results)} hosts")
        return len(all_enumeration_results) > 0

    async def vulnerability_detection_phase(self) -> bool:
        """Phase 3: CVE lookup and vulnerability identification"""
        logger.info("=== VULNERABILITY DETECTION PHASE ===")
        
        if not os.path.exists('vuln_detection.py'):
            logger.error("vuln_detection.py module not found")
            return False
            
        all_vulns = []
        
        # Extract unique services/products from enumeration results
        services_found = set()
        for host_data in self.results['enumeration']:
            for port_info in host_data['ports']:
                if port_info.get('service'):
                    services_found.add(port_info['service'])
                if port_info.get('product'):
                    services_found.add(port_info['product'])
                    
        logger.info(f"Searching vulnerabilities for {len(services_found)} unique services")
        
        # Query vulnerabilities for each service
        for service in services_found:
            if service and service.strip():
                vulns = self.run_module('vuln_detection.py', [service])
                if vulns:
                    for vuln in vulns:
                        vuln['related_service'] = service
                    all_vulns.extend(vulns)
                    
        self.results['vulnerabilities'] = all_vulns
        logger.info(f"Found {len(all_vulns)} potential vulnerabilities")
        return len(all_vulns) > 0

    async def deep_scan_phase(self, target: str) -> bool:
        """Phase 4: Deep credentialed scanning"""
        logger.info("=== DEEP SCAN PHASE ===")
        
        if not os.path.exists('deep_scan.py'):
            logger.error("deep_scan.py module not found")
            return False
            
        results = self.run_module('deep_scan.py', [target])
        if results is not None:
            self.results['deep_scan'] = results
            logger.info(f"Deep scan completed with {len(results)} findings")
            return True
        return False

    async def webapp_test_phase(self, target: str) -> bool:
        """Phase 5: Web application security testing"""
        logger.info("=== WEB APPLICATION TESTING PHASE ===")
        
        if not os.path.exists('web_test.py'):
            logger.error("web_test.py module not found")
            return False
            
        # Check if target has web services
        web_targets = []
        for host_data in self.results['enumeration']:
            for port_info in host_data['ports']:
                if port_info.get('service') in ['http', 'https', 'http-proxy']:
                    protocol = 'https' if port_info['port'] == 443 else 'http'
                    web_targets.append(f"{protocol}://{host_data['host']}:{port_info['port']}")
                    
        if not web_targets:
            # Try default web ports on target
            web_targets = [f"http://{target}", f"https://{target}"]
            
        all_webapp_results = []
        for web_target in web_targets:
            results = self.run_module('web_test.py', [web_target])
            if results:
                all_webapp_results.extend(results)
                
        self.results['webapp_findings'] = all_webapp_results
        logger.info(f"Web app testing found {len(all_webapp_results)} issues")
        return len(all_webapp_results) > 0

    async def compliance_check_phase(self, target: str) -> bool:
        """Phase 6: Compliance checking"""
        logger.info("=== COMPLIANCE CHECKING PHASE ===")
        
        if not os.path.exists('compliance.py'):
            logger.error("compliance.py module not found")
            return False
            
        results = self.run_module('compliance.py', [target])
        if results is not None:
            self.results['compliance'] = results
            logger.info(f"Compliance check completed with {len(results)} items")
            return True
        return False

    async def malware_scan_phase(self, target: str) -> bool:
        """Phase 7: Malware fingerprinting"""
        logger.info("=== MALWARE SCANNING PHASE ===")
        
        if not os.path.exists('malware_scan.py'):
            logger.error("malware_scan.py module not found")
            return False
            
        results = self.run_module('malware_scan.py', [target])
        if results is not None:
            self.results['malware_indicators'] = results
            logger.info(f"Malware scan found {len(results)} indicators")
            return True
        return False

    async def generate_reports(self, output_prefix: str = "vajra_report"):
        """Generate comprehensive reports"""
        logger.info("=== GENERATING REPORTS ===")
        
        # Update scan metadata
        self.results['scan_metadata']['end_time'] = datetime.now().isoformat()
        start_time = datetime.fromisoformat(self.results['scan_metadata']['start_time'])
        end_time = datetime.fromisoformat(self.results['scan_metadata']['end_time'])
        duration = (end_time - start_time).total_seconds()
        self.results['scan_metadata']['scan_duration'] = f"{duration:.2f} seconds"
        
        # Save raw results
        with open(f"{output_prefix}.json", 'w') as f:
            json.dump(self.results, f, indent=2)
            
        if os.path.exists('report_generator.py'):
            # Use the report generator module
            temp_file = "temp_results.json"
            with open(temp_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            self.run_module('report_generator.py', [temp_file])
            os.remove(temp_file)
        
        logger.info(f"Reports generated with prefix: {output_prefix}")

    async def run_full_scan(self, target: str, modules: List[str], output: str):
        """Execute the complete vulnerability assessment workflow"""
        logger.info(f"Starting Vajra scan on target: {target}")
        self.results['scan_metadata']['target'] = target
        
        # Phase execution based on selected modules
        if 'discovery' in modules:
            await self.discovery_phase(target)
            
        if 'enumeration' in modules:
            await self.enumeration_phase(target)
            
        if 'vulnerability' in modules:
            await self.vulnerability_detection_phase()
            
        if 'deep' in modules:
            await self.deep_scan_phase(target)
            
        if 'webapp' in modules:
            await self.webapp_test_phase(target)
            
        if 'compliance' in modules:
            await self.compliance_check_phase(target)
            
        if 'malware' in modules:
            await self.malware_scan_phase(target)
            
        # Always generate reports
        await self.generate_reports(output)
        
        # Summary
        total_issues = (len(self.results['vulnerabilities']) + 
                       len(self.results['webapp_findings']) + 
                       len(self.results['malware_indicators']))
        
        logger.info(f"Scan completed. Total issues found: {total_issues}")

def main():
    parser = argparse.ArgumentParser(
        description='Vajra - Comprehensive Vulnerability Assessment Tool',
        epilog='Example: python3 vajra.py 192.168.1.0/24 --modules discovery,enumeration,vulnerability'
    )
    
    parser.add_argument('target', help='Target IP, domain, or CIDR range')
    parser.add_argument('--modules', '-m', 
                       default='discovery,enumeration,vulnerability',
                       help='Comma-separated list of modules to run (discovery,enumeration,vulnerability,deep,webapp,compliance,malware)')
    parser.add_argument('--output', '-o', default='vajra_report',
                       help='Output file prefix for reports')
    parser.add_argument('--timeout', '-t', type=int, default=300,
                       help='Timeout for individual modules (seconds)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Parse modules
    available_modules = ['discovery', 'enumeration', 'vulnerability', 'deep', 'webapp', 'compliance', 'malware']
    selected_modules = [m.strip().lower() for m in args.modules.split(',')]
    
    # Validate modules
    invalid_modules = [m for m in selected_modules if m not in available_modules]
    if invalid_modules:
        logger.error(f"Invalid modules: {invalid_modules}")
        logger.error(f"Available modules: {available_modules}")
        sys.exit(1)
    
    # Initialize scanner
    scanner = VajraScanner()
    
    # Run the scan
    try:
        asyncio.run(scanner.run_full_scan(args.target, selected_modules, args.output))
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()