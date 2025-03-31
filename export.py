"""
Export module for generating vulnerability reports in PDF and Markdown formats
"""

import os
import markdown
from datetime import datetime
from xhtml2pdf import pisa

def generate_markdown_report(scan_results, scan_url):
    """
    Generate a markdown report from scan results
    
    Args:
        scan_results (dict): The scan results dictionary
        scan_url (str): The URL that was scanned
        
    Returns:
        str: The markdown formatted report
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Start with the header
    md_content = f"""# Security Scan Report for {scan_url}

**Scan Date:** {scan_results.get('timestamp', timestamp)}  
**Security Score:** {scan_results.get('security_score', 'N/A')}/100

"""
    
    # Add scan mode indicator
    if scan_results.get('is_demo', False):
        md_content += "> **Note:** This report was generated in DEMO MODE with simulated data.\n\n"
    elif scan_results.get('public_proxy_used', False):
        md_content += "> **Note:** This report was generated using a public Tor2web proxy service.\n\n"
    
    # Add summary section
    md_content += "## Summary\n\n"
    md_content += f"**URL:** {scan_url}  \n"
    md_content += f"**Status:** {'Reachable' if scan_results.get('reachable', False) else 'Unreachable'}  \n"
    
    if scan_results.get('reachable', False):
        md_content += f"**Response Time:** {scan_results.get('response_time', 'N/A')} seconds  \n"
        md_content += f"**Status Code:** {scan_results.get('status_code', 'N/A')}  \n"
    
    # Add severity counts
    severity_counts = scan_results.get('severity_counts', {})
    md_content += "\n### Issues Found\n\n"
    md_content += f"- **High:** {severity_counts.get('high', 0)}\n"
    md_content += f"- **Medium:** {severity_counts.get('medium', 0)}\n"
    md_content += f"- **Low:** {severity_counts.get('low', 0)}\n"
    md_content += f"- **Info:** {severity_counts.get('info', 0)}\n"
    
    # Add server information if available
    server_info = scan_results.get('server_info', {})
    if server_info:
        md_content += "\n### Server Information\n\n"
        for key, value in server_info.items():
            md_content += f"- **{key.capitalize()}:** {value}\n"
    
    # Add vulnerabilities section
    vulnerabilities = scan_results.get('vulnerabilities', [])
    if vulnerabilities:
        md_content += "\n## Vulnerabilities\n\n"
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').upper()
            md_content += f"### {vuln.get('name', 'Unknown Vulnerability')} ({severity})\n\n"
            md_content += f"{vuln.get('description', 'No description provided.')}\n\n"
            md_content += f"**Recommendation:** {vuln.get('recommendation', 'No recommendation provided.')}\n\n"
            md_content += "---\n\n"
    else:
        md_content += "\n## Vulnerabilities\n\n"
        md_content += "No vulnerabilities detected. This doesn't guarantee complete security, but the site passed our basic checks.\n\n"
    
    # Add HTTP Headers section if available
    headers = scan_results.get('headers', {})
    if headers:
        md_content += "## HTTP Headers\n\n"
        md_content += "| Header | Value |\n"
        md_content += "| ------ | ----- |\n"
        for header, value in headers.items():
            # Escape pipe characters in markdown tables
            value_escaped = str(value).replace('|', '\\|')
            md_content += f"| {header} | {value_escaped} |\n"
    
    # Add Cookies section if available
    cookies = scan_results.get('cookies', {})
    if cookies:
        md_content += "\n## Cookies\n\n"
        md_content += "| Name | Secure | HttpOnly |\n"
        md_content += "| ---- | ------ | -------- |\n"
        for name, cookie in cookies.items():
            secure = "Yes" if cookie.get('secure', False) else "No"
            httponly = "Yes" if cookie.get('httponly', False) else "No"
            md_content += f"| {name} | {secure} | {httponly} |\n"
    
    # Add Forms section if available
    forms = scan_results.get('forms', [])
    if forms:
        md_content += "\n## Forms\n\n"
        for i, form in enumerate(forms):
            md_content += f"### Form #{i+1}\n\n"
            md_content += f"**Action:** {form.get('action', 'N/A')}  \n"
            md_content += f"**Method:** {form.get('method', 'GET')}  \n"
            md_content += f"**CSRF Protection:** {'Yes' if form.get('has_csrf_token', False) else 'No'}  \n"
            
            if form.get('inputs', []):
                md_content += "\n**Inputs:**\n\n"
                md_content += "| Name | Type | Required |\n"
                md_content += "| ---- | ---- | -------- |\n"
                for input_field in form.get('inputs', []):
                    name = input_field.get('name', 'N/A')
                    type_ = input_field.get('type', 'text')
                    required = "Yes" if input_field.get('required', False) else "No"
                    md_content += f"| {name} | {type_} | {required} |\n"
    
    # Add footer
    md_content += "\n---\n"
    md_content += f"Report generated by Onion Scanner on {timestamp}\n"
    
    return md_content

def convert_html_to_pdf(source_html, output_filename):
    """
    Convert HTML content to PDF file
    
    Args:
        source_html (str): HTML content to convert
        output_filename (str): Path to save the PDF file
        
    Returns:
        bool: True if conversion was successful, False otherwise
    """
    # Create a PDF file
    with open(output_filename, "wb") as output_file:
        # Convert HTML to PDF
        conversion_status = pisa.CreatePDF(
            source_html,  # the HTML to convert
            dest=output_file  # the file handle to receive the PDF
        )
    
    # Return True on success and False on errors
    return conversion_status.err == 0

def generate_pdf_report(scan_results, scan_url, output_path=None):
    """
    Generate a PDF report from scan results
    
    Args:
        scan_results (dict): The scan results dictionary
        scan_url (str): The URL that was scanned
        output_path (str, optional): Path to save the PDF file. If None, a temporary file is created.
        
    Returns:
        str: The path to the generated PDF file
    """
    # Generate markdown content first
    md_content = generate_markdown_report(scan_results, scan_url)
    
    # Convert markdown to HTML
    html_content = markdown.markdown(md_content, extensions=['tables'])
    
    # Add CSS styling for better PDF rendering
    styled_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Security Scan Report - {scan_url}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 20px;
                color: #333;
            }}
            h1 {{
                color: #2c3e50;
                border-bottom: 2px solid #3498db;
                padding-bottom: 10px;
            }}
            h2, h3 {{
                color: #2c3e50;
                margin-top: 20px;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                margin: 15px 0;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            .severity-high {{
                color: #e74c3c;
                font-weight: bold;
            }}
            .severity-medium {{
                color: #f39c12;
                font-weight: bold;
            }}
            .severity-low {{
                color: #3498db;
                font-weight: bold;
            }}
            .note {{
                background-color: #f8f9fa;
                border-left: 4px solid #3498db;
                padding: 10px;
                margin: 10px 0;
            }}
            hr {{
                border: 0;
                border-top: 1px solid #eee;
                margin: 20px 0;
            }}
            .footer {{
                margin-top: 30px;
                font-size: 12px;
                color: #7f8c8d;
                text-align: center;
            }}
        </style>
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """
    
    # Create custom filename with URL and timestamp
    if output_path is None:
        sanitized_url = scan_url.replace('http://', '').replace('https://', '').replace('/', '_').replace('.', '_')
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_path = f"scan_report_{sanitized_url}_{timestamp}.pdf"
    
    # Convert to PDF and return the file path
    if convert_html_to_pdf(styled_html, output_path):
        return output_path
    return None