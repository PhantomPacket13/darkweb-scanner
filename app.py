import os
import logging
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, Response
from scanner import OnionScanner
from export import generate_markdown_report, generate_pdf_report

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")

# Default Tor configuration
DEFAULT_TOR_HOST = '127.0.0.1'
DEFAULT_TOR_PORT = 9050
DEFAULT_DEMO_MODE = False

# Initialize the scanner with configurable settings
scanner = OnionScanner(
    demo_mode=DEFAULT_DEMO_MODE,
    tor_host=DEFAULT_TOR_HOST,
    tor_port=DEFAULT_TOR_PORT
)

@app.route('/')
def index():
    """Render the main page with the scan form"""
    # Get current scanner settings from session if available
    scanner_settings = session.get('scanner_settings', {
        'demo_mode': scanner.demo_mode,
        'tor_host': scanner.tor_host,
        'tor_port': scanner.tor_port
    })
    
    return render_template('index.html', 
                          now=datetime.now(),
                          scanner_settings=scanner_settings)

@app.route('/scan', methods=['POST'])
def scan():
    """Handle the scan request and redirect to results page"""
    # Get the URL from the form
    onion_url = request.form.get('onion_url', '').strip()
    
    # Basic validation
    if not onion_url:
        flash("Please enter a URL to scan", "danger")
        return redirect(url_for('index'))
    
    if not onion_url.endswith('.onion') and not onion_url.startswith('http'):
        flash("Please enter a valid .onion URL", "danger")
        return redirect(url_for('index'))
    
    # Add protocol if not present
    if not onion_url.startswith('http'):
        onion_url = 'http://' + onion_url
    
    # First try using the demo scanner regardless of regular mode setting
    # This ensures we always have fallback data
    try:
        logger.info(f"Preparing demo results as fallback for {onion_url}")
        demo_scanner = OnionScanner(demo_mode=True)
        demo_results = demo_scanner.scan(onion_url)
        
        # Now try the real scan if we're not in demo mode
        if not scanner.demo_mode:
            try:
                logger.info(f"Starting real scan for {onion_url}")
                # Use the demo results as a fallback in case real scan fails
                scan_results = scanner.scan(onion_url)
                
                # Store real results in session
                session['scan_results'] = scan_results
                session['scanned_url'] = onion_url
                
                # Check if we had to use demo mode anyway and warn the user
                if scan_results.get('is_demo'):
                    flash("Tor connection not available. Showing simulated scan results in demo mode.", "warning")
                
                # Redirect to results page
                return redirect(url_for('results'))
                
            except Exception as e:
                # If real scan fails, use the demo results we already generated
                logger.error(f"Real scan error: {str(e)}")
                logger.info("Falling back to demo mode")
                
                # Store demo results in session
                session['scan_results'] = demo_results
                session['scanned_url'] = onion_url
                
                flash("Tor connection failed. Showing simulated scan results in demo mode.", "warning")
                return redirect(url_for('results'))
        else:
            # We're in demo mode, use the demo results
            session['scan_results'] = demo_results
            session['scanned_url'] = onion_url
            
            flash("Running in demo mode. Showing simulated scan results.", "info")
            return redirect(url_for('results'))
            
    except Exception as e:
        # This should rarely happen since demo mode should always work
        logger.error(f"Scan completely failed: {str(e)}")
        flash(f"Error scanning URL: {str(e)}", "danger")
        return redirect(url_for('index'))

@app.route('/results')
def results():
    """Show the results of a scan"""
    # Check if we have results in the session
    if 'scan_results' not in session or 'scanned_url' not in session:
        flash("No scan results available. Please perform a scan first.", "warning")
        return redirect(url_for('index'))
    
    # Get results from session
    scan_results = session['scan_results']
    scanned_url = session['scanned_url']
    
    # Log for debugging
    logger.info(f"Results page - vulnerabilities count: {len(scan_results.get('vulnerabilities', []))}")
    logger.info(f"First vulnerability name: {scan_results.get('vulnerabilities', [])[0].get('name') if scan_results.get('vulnerabilities', []) else 'None'}")
    
    # Calculate vulnerability statistics for charts
    vuln_stats = {
        'high': sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'high'),
        'medium': sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'medium'),
        'low': sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'low'),
        'info': sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'info')
    }
    
    # Ensure vulnerabilities is at least an empty list
    if 'vulnerabilities' not in scan_results:
        scan_results['vulnerabilities'] = []
        
    # Log for debugging
    logger.info(f"Vulnerability statistics: {vuln_stats}")
    
    return render_template('results.html', 
                          results=scan_results, 
                          url=scanned_url, 
                          vuln_stats=vuln_stats,
                          now=datetime.now())

@app.route('/report')
def report():
    """Generate a downloadable report"""
    # Check if we have results in the session
    if 'scan_results' not in session or 'scanned_url' not in session:
        flash("No scan results available. Please perform a scan first.", "warning")
        return redirect(url_for('index'))
    
    # Get results from session
    scan_results = session['scan_results']
    scanned_url = session['scanned_url']
    
    return render_template('report.html', 
                          results=scan_results, 
                          url=scanned_url,
                          now=datetime.now())

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return render_template('index.html', error="Page not found", now=datetime.now()), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    return render_template('index.html', error="Server error. Please try again later.", now=datetime.now()), 500

# Clear results
@app.route('/clear', methods=['POST'])
def clear_results():
    """Clear scan results from the session"""
    if 'scan_results' in session:
        del session['scan_results']
    if 'scanned_url' in session:
        del session['scanned_url']
    
    flash("Scan results cleared", "info")
    return redirect(url_for('index'))

# Export report as PDF
@app.route('/export/pdf')
def export_pdf():
    """Export scan results as PDF"""
    # Check if we have results in the session
    if 'scan_results' not in session or 'scanned_url' not in session:
        flash("No scan results available. Please perform a scan first.", "warning")
        return redirect(url_for('index'))
    
    # Get results from session
    scan_results = session['scan_results']
    scanned_url = session['scanned_url']
    
    # Generate sanitized filename for the PDF
    sanitized_url = scanned_url.replace('http://', '').replace('https://', '').replace('/', '_').replace('.', '_')
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"security_scan_{sanitized_url}_{timestamp}.pdf"
    
    # Generate the PDF file
    pdf_path = generate_pdf_report(scan_results, scanned_url, f"static/reports/{filename}")
    
    if pdf_path:
        # Send the file to the user
        return send_file(pdf_path, as_attachment=True, download_name=filename)
    else:
        flash("Error generating PDF report", "danger")
        return redirect(url_for('results'))

# Export report as Markdown
@app.route('/export/markdown')
def export_markdown():
    """Export scan results as Markdown"""
    # Check if we have results in the session
    if 'scan_results' not in session or 'scanned_url' not in session:
        flash("No scan results available. Please perform a scan first.", "warning")
        return redirect(url_for('index'))
    
    # Get results from session
    scan_results = session['scan_results']
    scanned_url = session['scanned_url']
    
    # Generate the markdown content
    markdown_content = generate_markdown_report(scan_results, scanned_url)
    
    # Generate sanitized filename for the markdown file
    sanitized_url = scanned_url.replace('http://', '').replace('https://', '').replace('/', '_').replace('.', '_')
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    filename = f"security_scan_{sanitized_url}_{timestamp}.md"
    
    # Return the markdown content as a downloadable file
    response = Response(
        markdown_content,
        mimetype="text/markdown",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )
    
    return response

# Debug route to see all vulnerabilities
@app.route('/debug/vulnerabilities')
def debug_vulnerabilities():
    """Debug route to list all vulnerabilities in the results"""
    if 'scan_results' not in session:
        return "No scan results in session"
    
    scan_results = session['scan_results']
    vulnerabilities = scan_results.get('vulnerabilities', [])
    
    result = "<h1>Vulnerabilities in Scan Results</h1>"
    if not vulnerabilities:
        result += "<p>No vulnerabilities found in results</p>"
    else:
        result += f"<p>Found {len(vulnerabilities)} vulnerabilities:</p><ul>"
        for vuln in vulnerabilities:
            result += f"<li><strong>{vuln.get('name')}</strong> - Severity: {vuln.get('severity')}</li>"
        result += "</ul>"
    
    return result

# Configure scanner settings
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """Configure scanner settings (Tor proxy, demo mode)"""
    global scanner
    
    if request.method == 'POST':
        # Get form data
        demo_mode = request.form.get('demo_mode') == 'on'
        tor_host = request.form.get('tor_host', DEFAULT_TOR_HOST)
        tor_port = int(request.form.get('tor_port', DEFAULT_TOR_PORT))
        
        # Update the scanner with new settings
        scanner = OnionScanner(
            demo_mode=demo_mode,
            tor_host=tor_host,
            tor_port=tor_port
        )
        
        # Save settings in session for display
        session['scanner_settings'] = {
            'demo_mode': demo_mode,
            'tor_host': tor_host,
            'tor_port': tor_port
        }
        
        flash("Scanner settings updated", "success")
        return redirect(url_for('index'))
    
    # For GET request, just show the settings form
    # Use current scanner settings or defaults
    current_settings = session.get('scanner_settings', {
        'demo_mode': scanner.demo_mode,
        'tor_host': scanner.tor_host,
        'tor_port': scanner.tor_port
    })
    
    return render_template('settings.html', 
                          settings=current_settings,
                          now=datetime.now())
