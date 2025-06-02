"""
Helper functions for Vajra Security Scanner
"""
import os
import json
import csv
import re
import socket
import ipaddress
from datetime import datetime
from pathlib import Path

def ensure_directories():
    """Ensure required directories exist"""
    directories = ['logs', 'output', 'reports', 'temp']
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")

def generate_report(results_dir='output', format='json'):
    """Generate consolidated report from all scan results"""
    if not os.path.exists(results_dir):
        print(f"Error: Results directory '{results_dir}' does not exist")
        return None
    
    consolidated_data = {
        'scan_summary': {
            'timestamp': datetime.now().isoformat(),
            'total_scans': 0,
            'total_vulnerabilities': 0,
            'scan_types': []
        },
        'results': []
    }
    
    # Collect all result files
    result_files = []
    for root, dirs, files in os.walk(results_dir):
        for file in files:
            if file.endswith('.json'):
                result_files.append(os.path.join(root, file))
    
    # Process each result file
    for file_path in result_files:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                consolidated_data['results'].append({
                    'file': os.path.basename(file_path),
                    'data': data
                })
                consolidated_data['scan_summary']['total_scans'] += 1
                
                # Count vulnerabilities if present
                if 'vulnerabilities' in data:
                    consolidated_data['scan_summary']['total_vulnerabilities'] += len(data['vulnerabilities'])
                
                # Track scan types
                if 'scan_type' in data and data['scan_type'] not in consolidated_data['scan_summary']['scan_types']:
                    consolidated_data['scan_summary']['scan_types'].append(data['scan_type'])
                    
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    
    # Generate output based on format
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if format.lower() == 'json':
        output_file = f"reports/consolidated_report_{timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(consolidated_data, f, indent=2)
        print(f"JSON report generated: {output_file}")
        return output_file
    
    elif format.lower() == 'html':
        output_file = f"reports/consolidated_report_{timestamp}.html"
        export_to_html(consolidated_data, output_file)
        return output_file
    
    elif format.lower() == 'csv':
        output_file = f"reports/consolidated_report_{timestamp}.csv"
        export_to_csv(consolidated_data, output_file)
        return output_file
    
    else:
        print(f"Unsupported format: {format}")
        return None

def export_to_csv(data, filename):
    """Export data to CSV format"""
    try:
        ensure_directories()
        
        # Create CSV with flattened structure
        csv_data = []
        
        if isinstance(data, dict) and 'results' in data:
            # Handle consolidated report format
            for result in data['results']:
                if 'data' in result:
                    scan_data = result['data']
                    base_row = {
                        'source_file': result.get('file', ''),
                        'scan_type': scan_data.get('scan_type', ''),
                        'target': scan_data.get('target', ''),
                        'timestamp': scan_data.get('timestamp', ''),
                        'status': scan_data.get('status', '')
                    }
                    
                    # Add vulnerabilities if present
                    if 'vulnerabilities' in scan_data:
                        for vuln in scan_data['vulnerabilities']:
                            row = base_row.copy()
                            row.update({
                                'vulnerability_id': vuln.get('id', ''),
                                'severity': vuln.get('severity', ''),
                                'description': vuln.get('description', ''),
                                'port': vuln.get('port', ''),
                                'service': vuln.get('service', '')
                            })
                            csv_data.append(row)
                    else:
                        csv_data.append(base_row)
        else:
            # Handle simple data structure
            csv_data = [data] if isinstance(data, dict) else data
        
        if csv_data:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = csv_data[0].keys() if csv_data else []
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(csv_data)
            
            print(f"Data exported to CSV: {filename}")
        else:
            print("No data to export to CSV")
            
    except Exception as e:
        print(f"Error exporting to CSV: {e}")

def export_to_html(data, filename):
    """Export data to HTML format"""
    try:
        ensure_directories()
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vajra Security Scanner Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; text-align: center; }}
        h2 {{ color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .summary-item {{ display: inline-block; margin-right: 20px; }}
        .vulnerability {{ background: #fff; border-left: 4px solid #e74c3c; padding: 10px; margin: 10px 0; }}
        .vulnerability.high {{ border-left-color: #e74c3c; }}
        .vulnerability.medium {{ border-left-color: #f39c12; }}
        .vulnerability.low {{ border-left-color: #27ae60; }}
        .vulnerability.info {{ border-left-color: #3498db; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .timestamp {{ color: #7f8c8d; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Vajra Security Scanner Report</h1>
        <div class="timestamp">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
"""
        
        if isinstance(data, dict) and 'scan_summary' in data:
            summary = data['scan_summary']
            html_content += f"""
        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="summary-item"><strong>Total Scans:</strong> {summary.get('total_scans', 0)}</div>
            <div class="summary-item"><strong>Total Vulnerabilities:</strong> {summary.get('total_vulnerabilities', 0)}</div>
            <div class="summary-item"><strong>Scan Types:</strong> {', '.join(summary.get('scan_types', []))}</div>
        </div>
"""
            
            if 'results' in data:
                html_content += "<h2>Detailed Results</h2>"
                for result in data['results']:
                    if 'data' in result:
                        scan_data = result['data']
                        html_content += f"""
        <h3>Scan: {result.get('file', 'Unknown')}</h3>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Target</td><td>{scan_data.get('target', 'N/A')}</td></tr>
            <tr><td>Scan Type</td><td>{scan_data.get('scan_type', 'N/A')}</td></tr>
            <tr><td>Status</td><td>{scan_data.get('status', 'N/A')}</td></tr>
            <tr><td>Timestamp</td><td>{scan_data.get('timestamp', 'N/A')}</td></tr>
        </table>
"""
                        
                        if 'vulnerabilities' in scan_data:
                            html_content += "<h4>Vulnerabilities</h4>"
                            for vuln in scan_data['vulnerabilities']:
                                severity = vuln.get('severity', 'info').lower()
                                html_content += f"""
        <div class="vulnerability {severity}">
            <strong>{vuln.get('id', 'Unknown ID')}</strong> - {vuln.get('severity', 'Unknown').upper()}<br>
            <em>{vuln.get('description', 'No description available')}</em><br>
            Port: {vuln.get('port', 'N/A')} | Service: {vuln.get('service', 'N/A')}
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Data exported to HTML: {filename}")
        
    except Exception as e:
        print(f"Error exporting to HTML: {e}")

def validate_target(target):
    """Validate target IP/hostname"""
    if not target or not isinstance(target, str):
        print(f"Invalid target: {target} (must be a non-empty string)")
        return False
    
    target = target.strip()
    
    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(target)
        print(f"Valid IP address: {target}")
        return True
    except ValueError:
        pass
    
    # Check if it's a valid hostname/domain
    hostname_pattern = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$|'  # Single label
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z0-9-]{1,63})*$'  # Multi-label
    )
    
    if hostname_pattern.match(target):
        # Additional checks for hostname
        if len(target) > 253:
            print(f"Invalid target: {target} (hostname too long)")
            return False
        
        # Try to resolve the hostname
        try:
            socket.gethostbyname(target)
            print(f"Valid hostname: {target}")
            return True
        except socket.gaierror:
            print(f"Warning: Cannot resolve hostname: {target}")
            return True  # Still valid format, just unresolvable
    
    # Check for CIDR notation
    try:
        ipaddress.ip_network(target, strict=False)
        print(f"Valid IP network: {target}")
        return True
    except ValueError:
        pass
    
    print(f"Invalid target format: {target}")
    return False

def log_scan_result(target, scan_type, result, log_level='INFO'):
    """Log scan results to file"""
    ensure_directories()
    
    log_filename = f"logs/vajra_scan_{datetime.now().strftime('%Y%m%d')}.log"
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    log_entry = f"[{timestamp}] [{log_level}] Target: {target} | Type: {scan_type} | Result: {result}\n"
    
    try:
        with open(log_filename, 'a', encoding='utf-8') as log_file:
            log_file.write(log_entry)
    except Exception as e:
        print(f"Error writing to log file: {e}")

def save_scan_result(target, scan_type, results, output_dir='output'):
    """Save individual scan results to JSON file"""
    ensure_directories()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/{scan_type}_{target.replace('.', '_')}_{timestamp}.json"
    
    scan_data = {
        'target': target,
        'scan_type': scan_type,
        'timestamp': datetime.now().isoformat(),
        'status': 'completed',
        'results': results
    }
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(scan_data, f, indent=2)
        print(f"Scan results saved: {filename}")
        return filename
    except Exception as e:
        print(f"Error saving scan results: {e}")
        return None

def get_scan_statistics(results_dir='output'):
    """Get statistics about completed scans"""
    if not os.path.exists(results_dir):
        return {'error': 'Results directory does not exist'}
    
    stats = {
        'total_scans': 0,
        'scan_types': {},
        'targets_scanned': set(),
        'date_range': {'earliest': None, 'latest': None}
    }
    
    for root, dirs, files in os.walk(results_dir):
        for file in files:
            if file.endswith('.json'):
                try:
                    with open(os.path.join(root, file), 'r') as f:
                        data = json.load(f)
                        
                        stats['total_scans'] += 1
                        
                        # Track scan types
                        scan_type = data.get('scan_type', 'unknown')
                        stats['scan_types'][scan_type] = stats['scan_types'].get(scan_type, 0) + 1
                        
                        # Track targets
                        if 'target' in data:
                            stats['targets_scanned'].add(data['target'])
                        
                        # Track date range
                        if 'timestamp' in data:
                            scan_date = data['timestamp']
                            if stats['date_range']['earliest'] is None or scan_date < stats['date_range']['earliest']:
                                stats['date_range']['earliest'] = scan_date
                            if stats['date_range']['latest'] is None or scan_date > stats['date_range']['latest']:
                                stats['date_range']['latest'] = scan_date
                
                except Exception as e:
                    print(f"Error processing {file}: {e}")
    
    stats['unique_targets'] = len(stats['targets_scanned'])
    stats['targets_scanned'] = list(stats['targets_scanned'])
    
    return stats