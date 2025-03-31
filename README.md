# Dark Web Security Scanner

A specialized web application designed for comprehensive security vulnerability scanning of .onion dark web sites using advanced network analysis techniques.

## Features

- Scan .onion sites for common security vulnerabilities
- Detailed vulnerability reporting with severity ratings
- Multiple operational modes: local Tor, public proxy, and demo mode
- Export reports to PDF and Markdown formats
- Settings customization for different connection methods
- Android compatibility via Orbot proxy integration

## Requirements

- Python 3.6+
- Flask
- PySocks (for Tor connectivity)
- Trafilatura (for content extraction)
- xhtml2pdf (for PDF report generation)

## Installation

1. Clone this repository:
```
git clone https://github.com/yourusername/darkweb-security-scanner.git
cd darkweb-security-scanner
```

2. Install the required dependencies:
```
pip install -r requirements.txt
```

3. Run the application:
```
python main.py
```

The application will be accessible at http://localhost:5000.

## Operational Modes

### Demo Mode
Generates simulated security scan results without requiring Tor connectivity. Use this mode for testing or demonstration purposes.

### Local Tor Mode
Connects to a local Tor service running on your machine. This provides the most secure and reliable scanning capability.

### Public Proxy Mode
Uses public Tor2web gateway services to access .onion sites when a local Tor connection isn't available. This mode is less secure but more convenient.

### Android (Orbot) Mode
Compatible with Orbot on Android devices. Configure Orbot to provide a SOCKS proxy, then enter the appropriate settings in the application.

## Security Notes

- Only scan sites you own or have explicit permission to test
- This tool is provided for educational and defensive security purposes only
- Be aware that scanning may generate significant traffic to the target site
- Some scans may trigger intrusion detection systems

## License

This project is licensed under the MIT License - see the LICENSE file for details.