# Installation and Development Guide

This document provides detailed instructions for setting up the Dark Web Security Scanner project for development or deployment.

## Prerequisites

- Python 3.6 or higher
- pip (Python package installer)
- Tor service (optional, but required for real scanning)

## Local Development Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/darkweb-security-scanner.git
cd darkweb-security-scanner
```

2. Create a virtual environment:
```bash
python -m venv venv
```

3. Activate the virtual environment:
   - On Windows:
   ```bash
   venv\Scripts\activate
   ```
   - On macOS and Linux:
   ```bash
   source venv/bin/activate
   ```

4. Install the dependencies:
```bash
pip install -r dependencies.txt
```

5. Run the application:
```bash
python main.py
```

The application will be accessible at http://localhost:5000.

## Setting Up Tor for Local Development

### On Linux
```bash
sudo apt-get install tor
sudo systemctl start tor
```

### On macOS (using Homebrew)
```bash
brew install tor
brew services start tor
```

### On Windows
1. Download the Tor Browser from https://www.torproject.org/
2. Install and run the Tor Browser
3. The Tor SOCKS proxy will be available at 127.0.0.1:9050 while the browser is running

## Android Development (with Orbot)

1. Install Orbot from Google Play Store or F-Droid
2. Configure Orbot to provide a SOCKS proxy (typically on port 9050)
3. In the scanner settings, enter 127.0.0.1 as the host and the configured port

## Docker Deployment

1. Build the Docker image:
```bash
docker build -t onion-scanner .
```

2. Run the container:
```bash
docker run -p 5000:5000 onion-scanner
```

The application will be accessible at http://localhost:5000.

## Heroku Deployment

1. Create a Heroku account and install the Heroku CLI
2. Login to Heroku:
```bash
heroku login
```

3. Create a new Heroku app:
```bash
heroku create your-app-name
```

4. Deploy the application:
```bash
git push heroku main
```

Note: Since Heroku doesn't include Tor by default, the scanner will automatically operate in public proxy mode or demo mode.

## Configuration Options

- **Demo Mode**: Generates simulated scan results without requiring Tor
- **Local Tor**: Uses a local Tor service for scanning (most secure)
- **Public Proxy**: Uses Tor2web gateways when local Tor isn't available
- **Android/Orbot**: Uses Orbot as the Tor proxy on Android devices