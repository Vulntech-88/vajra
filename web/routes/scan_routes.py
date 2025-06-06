from datetime import datetime
import os
import json
import uuid
from flask import Blueprint, current_app, render_template, request, flash, redirect, url_for, abort
from werkzeug.utils import secure_filename

from web.forms.scan_forms import ScanForm
from main import VajraScanner

scan_bp = Blueprint('scan', __name__)

@scan_bp.route('/scan', methods=['GET', 'POST'])
def scan_page():
    form = ScanForm()
    scan_result = None
    error_message = None

    if form.validate_on_submit():
        try:
            target = form.target.data.strip()
            if not target:
                flash("Please enter a valid target URL or IP address.", "warning")
                return render_template('scan.html', form=form)

            # Validate target format
            if not (target.startswith(('http://', 'https://')) or 
                   all(c.isdigit() or c == '.' for c in target)):
                flash("Please enter a valid URL (starting with http:// or https://) or IP address.", "warning")
                return render_template('scan.html', form=form)

            scan_id = str(uuid.uuid4())
            
            # Run the CLI scan logic
            scanner = VajraScanner(target)
            scanner.run_full_scan()

            # Locate the result JSON file
            result_file = f"output/vajra_full_scan_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            if os.path.exists(result_file):
                with open(result_file, 'r') as f:
                    scan_result = json.load(f)
                flash("Scan completed successfully!", "success")
            else:
                flash("Scan completed but result file not found.", "warning")
                
        except Exception as e:
            flash(f"An error occurred during the scan: {str(e)}", "danger")
            return render_template('scan.html', form=form, error_message=str(e))

    return render_template('scan.html', form=form, scan_result=scan_result)

@scan_bp.route('/scan/history')
def scan_history():
    # Get list of scan results from output directory
    scan_files = []
    output_dir = "output"
    
    if os.path.exists(output_dir):
        for file in os.listdir(output_dir):
            if file.endswith('.json'):
                file_path = os.path.join(output_dir, file)
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        scan_files.append({
                            'filename': file,
                            'timestamp': os.path.getmtime(file_path),
                            'target': data.get('target', 'Unknown')
                        })
                except:
                    continue
    
    # Sort by timestamp, newest first
    scan_files.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('scan_history.html', scan_history=scan_files)

@scan_bp.route('/scan/view/<filename>')
def view_scan(filename):
    # Secure the filename to prevent directory traversal
    filename = secure_filename(filename)
    file_path = os.path.join('output', filename)
    
    if not os.path.exists(file_path):
        abort(404)
        
    try:
        with open(file_path, 'r') as f:
            scan_data = json.load(f)
        return render_template('scan_result.html', scan_data=scan_data, filename=filename)
    except Exception as e:
        current_app.logger.error(f"Error reading scan result: {str(e)}")
        flash(f"Error reading scan result: {str(e)}", "danger")
        return redirect(url_for('scan.scan_history'))
