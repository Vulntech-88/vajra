"""
Helper functions for Vajra Security Scanner
"""
import os
import json
import csv
from datetime import datetime

def ensure_directories():
    """Ensure required directories exist"""
    directories = ['logs', 'output']
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")

def generate_report(results_dir='output', format='json'):
    """Generate consolidated report from all scan results"""
    # TODO: Implement report generation logic
    print(f"Generating {format} report from {results_dir}")
    pass

def export_to_csv(data, filename):
    """Export data to CSV format"""
    # TODO: Implement CSV export logic
    print(f"Exporting data to {filename}")
    pass

def export_to_html(data, filename):
    """Export data to HTML format"""
    # TODO: Implement HTML export logic
    print(f"Exporting data to {filename}")
    pass

def validate_target(target):
    """Validate target IP/hostname"""
    # TODO: Implement target validation logic
    print(f"Validating target: {target}")
    return True
