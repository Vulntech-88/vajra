"""
Vajra Security Scanner - Main Controller
"""
import sys
import argparse
import json
from datetime import datetime

# Import all scanner modules
from modules.discovery import DiscoveryScanner
from modules.enumeration import EnumerationScanner
from modules.vulnerability_detection import VulnerabilityScanner
from modules.deep_scan import DeepScanner
from modules.web_testing import WebTestingScanner
from modules.compliance import ComplianceScanner
from modules.malware_scan import MalwareScanner
from utils.helpers import ensure_directories, generate_report

class VajraScanner:
    def __init__(self, target):
        self.target = target
        self.results = {}
        
    def run_full_scan(self):
        """Execute complete security scan workflow"""
        print(f"Starting Vajra Security Scanner for target: {self.target}")
        print("=" * 60)
        
        # Ensure required directories exist
        ensure_directories()
        
        # Phase 1: Discovery
        print("\n[PHASE 1] Discovery")
        discovery = DiscoveryScanner(self.target)
        self.results['discovery'] = discovery.run()
        
        # Phase 2: Enumeration
        print("\n[PHASE 2] Enumeration")
        enumeration = EnumerationScanner(self.target, self.results['discovery'])
        self.results['enumeration'] = enumeration.run()
        
        # Phase 3: Vulnerability Detection
        print("\n[PHASE 3] Vulnerability Detection")
        vuln_scan = VulnerabilityScanner(self.target, self.results['enumeration'])
        self.results['vulnerability'] = vuln_scan.run()
        
        # Phase 4: Deep Scanning
        print("\n[PHASE 4] Deep Scanning")
        deep_scan = DeepScanner(self.target)
        self.results['deep_scan'] = deep_scan.run()
        
        # Phase 5: Web Application Testing
        print("\n[PHASE 5] Web Application Testing")
        web_test = WebTestingScanner(self.target)
        self.results['web_testing'] = web_test.run()
        
        # Phase 6: Compliance Checking
        print("\n[PHASE 6] Compliance Checking")
        compliance = ComplianceScanner(self.target)
        self.results['compliance'] = compliance.run()
        
        # Phase 7: Malware Scanning
        print("\n[PHASE 7] Malware Scanning")
        malware = MalwareScanner(self.target)
        self.results['malware'] = malware.run()
        
        # Phase 8: Generate Reports
        print("\n[PHASE 8] Generating Reports")
        self._generate_final_report()
        
        print("\n" + "=" * 60)
        print("Vajra Security Scanner completed successfully!")
        
    def _generate_final_report(self):
        """Generate final consolidated report"""
        # TODO: Implement comprehensive report generation
        print("Generating final consolidated report...")
        
        # Save consolidated results
        filename = f"output/vajra_full_scan_{self.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"Full scan results saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(description='Vajra Security Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('--module', choices=['discovery', 'enumeration', 'vulnerability', 'deep', 'web', 'compliance', 'malware'], 
                       help='Run specific module only')
    
    args = parser.parse_args()
    
    scanner = VajraScanner(args.target)
    
    if args.module:
        # Run specific module only
        print(f"Running {args.module} module for target: {args.target}")
        # TODO: Implement individual module execution
    else:
        # Run full scan
        scanner.run_full_scan()

if __name__ == "__main__":
    main()
