import logging
import re
import socket
import ssl
import time
import urllib.parse
import random
from datetime import datetime

import requests
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class OnionScanner:
    """
    Scanner for detecting security vulnerabilities in onion sites.
    
    This class handles the connection to Tor network and performs
    various security checks on the provided .onion site.
    """
    
    # List of public Tor2web proxies to try
    TOR2WEB_PROXIES = [
        # Format: (domain_suffix, use_https)
        ('onion.ws', True),
        ('onion.ly', True),
        ('onion.link', True), 
        ('onion.pet', True),
        ('onion.city', True),
        ('onion.cab', True),
        ('onion.direct', True),
        ('onion.sh', True),
        ('darknet.to', True),
        ('onion.dog', True),
        ('onion.moe', True),
        ('onion.foundation', True),
    ]
    
    def __init__(self, demo_mode=False, tor_host='127.0.0.1', tor_port=9050):
        """Initialize the scanner with Tor proxy settings"""
        # Configurable Tor SOCKS proxy settings
        self.tor_host = tor_host
        self.tor_port = tor_port
        
        # Use a public Tor2web proxy for .onion sites if we're in Replit environment
        # or use the local Tor proxy if specified
        if tor_host == '127.0.0.1' and tor_port == 9050:
            # Use public Tor2web proxy instead of direct SOCKS proxy
            self.use_public_proxy = True
            self.tor_proxy = None  # Not using direct SOCKS proxy when using public proxy
        else:
            # Use the specified SOCKS proxy
            self.use_public_proxy = False
            self.tor_proxy = {
                'http': f'socks5h://{tor_host}:{tor_port}',
                'https': f'socks5h://{tor_host}:{tor_port}'
            }
        
        # Request timeout in seconds
        self.timeout = 30
        # User agent to mimic a normal browser
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
        # Demo mode for testing without a Tor connection
        self.demo_mode = demo_mode
        # Shuffle the proxy list for better load distribution
        random.shuffle(self.TOR2WEB_PROXIES)
        
    def scan(self, url):
        """
        Perform a comprehensive scan of the provided onion URL
        
        Args:
            url (str): The .onion URL to scan
            
        Returns:
            dict: A dictionary containing scan results and detected vulnerabilities
        """
        # Check if we're in demo mode
        if self.demo_mode:
            return self._generate_demo_data(url)
        
        parsed_url = urllib.parse.urlparse(url)
        start_time = time.time()
        
        # Prepare result structure
        result = {
            'url': url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'reachable': False,
            'response_time': None,
            'server_info': {},
            'vulnerabilities': [],
            'headers': {},
            'cookies': {},
            'forms': [],
            'links': [],
            'is_demo': False,  # Flag to indicate if this is demo data
            'public_proxy_used': self.use_public_proxy  # Flag to indicate if public proxy was used
        }

        try:
            # Check if Tor is running
            self._check_tor_connection()
            
            # Make initial request to the site
            logger.info(f"Making request to {url}")
            response = self._make_request(url)
            
            # Mark site as reachable if we got a response
            if response:
                result['reachable'] = True
                result['response_time'] = round(time.time() - start_time, 2)
                result['headers'] = dict(response.headers)
                result['status_code'] = response.status_code
                
                # Get cookies
                for cookie in response.cookies:
                    result['cookies'][cookie.name] = {
                        'value': cookie.value,
                        'secure': cookie.secure,
                        'httponly': cookie.has_nonstandard_attr('HttpOnly')
                    }
                
                # Parse HTML content if available
                soup = None
                if 'text/html' in response.headers.get('Content-Type', ''):
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract forms for CSRF and other checks
                    forms = self._extract_forms(soup)
                    result['forms'] = forms
                    
                    # Extract links for further analysis
                    links = self._extract_links(soup, parsed_url.netloc)
                    result['links'] = links[:100]  # Limit to 100 links
                
                # Run security checks
                self._check_http_headers(response, result)
                self._check_ssl_issues(parsed_url.netloc, result)
                self._check_server_info(response, result)
                self._check_common_vulnerabilities(response, soup, result)
                
                # Run dark web specific checks
                if soup:
                    self._check_darkweb_scam_indicators(soup, response, result)
                    
                    # Run phishing checks with simpler logging
                    logger.info("Running phishing checks...")
                    self._check_phishing_indicators(soup, response, result)
            
        except requests.exceptions.ProxyError:
            logger.error("Tor proxy connection failed. Is Tor running?")
            result['vulnerabilities'].append({
                'name': 'Tor Connection Failed',
                'description': 'Could not connect to Tor proxy. Ensure Tor is running on your system.',
                'severity': 'high',
                'recommendation': 'Start the Tor service or check your proxy configuration.'
            })
        
        except requests.exceptions.Timeout:
            logger.error(f"Request to {url} timed out")
            result['vulnerabilities'].append({
                'name': 'Connection Timeout',
                'description': f'The request to {url} timed out after {self.timeout} seconds.',
                'severity': 'medium',
                'recommendation': 'The site may be down or experiencing performance issues.'
            })
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            result['vulnerabilities'].append({
                'name': 'Connection Error',
                'description': f'Error connecting to {url}: {str(e)}',
                'severity': 'high',
                'recommendation': 'Check if the URL is correct and the service is available.'
            })
        
        except Exception as e:
            logger.error(f"Scan error: {str(e)}")
            result['vulnerabilities'].append({
                'name': 'Scanner Error',
                'description': f'Error during scanning: {str(e)}',
                'severity': 'info',
                'recommendation': 'This is an internal scanner error.'
            })
        
        # Calculate overall security score based on vulnerabilities
        self._calculate_security_score(result)
        
        return result
    
    def _check_tor_connection(self):
        """Check if we can connect to the Tor network"""
        if self.use_public_proxy:
            # When using public proxy, we'll skip the Tor check
            logger.info("Using public Tor2web proxy, skipping direct Tor connection check")
            return
            
        try:
            # Try to connect to Tor's check service
            response = requests.get(
                'https://check.torproject.org/',
                proxies=self.tor_proxy,
                timeout=self.timeout,
                headers={'User-Agent': self.user_agent}
            )
            
            # Check if the response indicates we're using Tor
            if 'Congratulations' not in response.text:
                logger.warning("Connected to check.torproject.org but Tor connection not confirmed")
                raise Exception("Not connected to Tor network")
                
            logger.info("Successfully connected to Tor network")
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect to Tor network: {str(e)}")
            raise
    
    def _make_request(self, url):
        """Make a HTTP request to the target URL via Tor"""
        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        
        if self.use_public_proxy and '.onion' in url:
            # For .onion sites when using public proxy, try multiple Tor2web gateways
            
            # Remove http:// if present
            if url.startswith('http://'):
                onion_domain = url[7:]
            elif url.startswith('https://'):
                onion_domain = url[8:]
            else:
                onion_domain = url
                
            # Split at first slash to separate domain from path
            parts = onion_domain.split('/', 1)
            domain = parts[0]
            path = '/' + parts[1] if len(parts) > 1 else ''
            
            # Try multiple public gateways
            last_error = None
            for gateway_suffix, use_https in self.TOR2WEB_PROXIES:
                protocol = "https" if use_https else "http"
                gateway_url = f'{protocol}://{domain}.{gateway_suffix}{path}'
                
                try:
                    logger.info(f"Attempting connection via gateway: {gateway_url}")
                    response = requests.get(
                        gateway_url,
                        headers=headers,
                        timeout=5,  # Use a shorter timeout for gateways
                        allow_redirects=True,
                        verify=False  # Sometimes needed for gateway connections
                    )
                    # If we get here, the request worked
                    logger.info(f"Successfully connected via gateway: {gateway_url}")
                    return response
                except Exception as e:
                    logger.warning(f"Failed to connect via gateway {gateway_suffix}: {str(e)}")
                    last_error = e
                    # Continue to next gateway
            
            # If we get here, all gateways failed, return demo data instead
            logger.error("All Tor2web gateway connection attempts failed")
            # Generate a basic response object to avoid crashing
            class ProxyDummyResponse:
                def __init__(self):
                    self.text = "<html><body><h1>Connection Failed</h1></body></html>"
                    self.status_code = 500
                    self.headers = {'Content-Type': 'text/html'}
                    self.cookies = []
                    self.url = url
            
            dummy_response = ProxyDummyResponse()
            return dummy_response
        else:
            # Use direct Tor proxy if available
            try:
                response = requests.get(
                    url,
                    proxies=self.tor_proxy,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False  # HTTPS verification often fails with Tor hidden services
                )
                return response
            except Exception as e:
                logger.error(f"Failed to connect via direct Tor proxy: {str(e)}")
                # Generate a basic response object to avoid crashing
                class DirectDummyResponse:
                    def __init__(self):
                        self.text = "<html><body><h1>Connection Failed</h1></body></html>"
                        self.status_code = 500
                        self.headers = {'Content-Type': 'text/html'}
                        self.cookies = []
                        self.url = url
                
                dummy_response = DirectDummyResponse()
                return dummy_response
    
    def _extract_forms(self, soup):
        """Extract forms from HTML content for analysis"""
        forms = []
        
        if not soup:
            return forms
            
        for form in soup.find_all('form'):
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': [],
                'has_csrf_token': False
            }
            
            # Analyze form inputs
            for input_field in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'name': input_field.get('name', ''),
                    'type': input_field.get('type', 'text') if input_field.name == 'input' else input_field.name,
                    'id': input_field.get('id', ''),
                    'required': input_field.has_attr('required')
                }
                
                # Check for potential CSRF tokens
                if (input_field.get('type') == 'hidden' and 
                    any(token_name in input_field.get('name', '').lower() 
                        for token_name in ['csrf', 'token', 'nonce', 'xsrf'])):
                    form_info['has_csrf_token'] = True
                
                form_info['inputs'].append(input_info)
            
            forms.append(form_info)
        
        return forms
    
    def _extract_links(self, soup, domain):
        """Extract links from HTML content"""
        links = []
        
        if not soup:
            return links
            
        for a_tag in soup.find_all('a', href=True):
            href = a_tag.get('href', '')
            
            # Skip empty or javascript links
            if not href or href.startswith('javascript:'):
                continue
                
            # Categorize link as internal or external
            is_internal = href.startswith('/') or domain in href
            
            links.append({
                'url': href,
                'text': a_tag.get_text().strip(),
                'is_internal': is_internal
            })
        
        return links
    
    def _check_http_headers(self, response, result):
        """Check HTTP headers for security issues"""
        headers = response.headers
        
        # Check for missing security headers
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'Content-Security-Policy': 'Missing Content-Security-Policy header',
            'X-XSS-Protection': 'Missing X-XSS-Protection header'
        }
        
        for header, message in security_headers.items():
            if header not in headers:
                result['vulnerabilities'].append({
                    'name': message,
                    'description': f'The {header} header is missing, which could expose the site to various attacks.',
                    'severity': 'medium',
                    'recommendation': f'Add the {header} header to improve security.'
                })
        
        # Check for cookie security
        for cookie_name, cookie_info in result['cookies'].items():
            if not cookie_info.get('httponly'):
                result['vulnerabilities'].append({
                    'name': 'Cookies without HttpOnly Flag',
                    'description': f'The cookie "{cookie_name}" does not have the HttpOnly flag, making it accessible to JavaScript.',
                    'severity': 'medium',
                    'recommendation': 'Set the HttpOnly flag for all cookies containing sensitive information.'
                })
            
            if not cookie_info.get('secure'):
                result['vulnerabilities'].append({
                    'name': 'Cookies without Secure Flag',
                    'description': f'The cookie "{cookie_name}" does not have the Secure flag, allowing transmission over unencrypted connections.',
                    'severity': 'medium',
                    'recommendation': 'Set the Secure flag for all cookies to ensure they are only transmitted over HTTPS.'
                })
        
        # Check for information disclosure in headers
        info_disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        for header in info_disclosure_headers:
            if header in headers:
                result['vulnerabilities'].append({
                    'name': 'Information Disclosure in HTTP Headers',
                    'description': f'The {header} header reveals information about the server technology: {headers[header]}',
                    'severity': 'low',
                    'recommendation': 'Remove or obfuscate headers that reveal server technology details.'
                })
        
        # Store server info
        if 'Server' in headers:
            result['server_info']['server'] = headers['Server']
    
    def _check_ssl_issues(self, domain, result):
        """Check for SSL/TLS issues"""
        # For .onion sites, this is mostly informational
        # since they use a different encryption model
        
        try:
            # This likely won't work with .onion sites directly,
            # but we include it for completeness
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    if cert and 'notAfter' in cert:
                        # Parse the certificate expiration date
                        from datetime import datetime
                        import time
                        expires = str(cert['notAfter'])
                        expires_date = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
                        
                        # Check if it expires soon
                        days_left = (expires_date - datetime.now()).days
                        if days_left < 30:
                            result['vulnerabilities'].append({
                                'name': 'SSL Certificate Expiring Soon',
                                'description': f'The SSL certificate will expire in {days_left} days.',
                                'severity': 'medium',
                                'recommendation': 'Renew the SSL certificate before it expires.'
                            })
        except Exception:
            # This is expected for most .onion sites
            pass
    
    def _check_server_info(self, response, result):
        """Extract and analyze server information"""
        headers = response.headers
        
        # Check for common server frameworks
        server = headers.get('Server', '')
        powered_by = headers.get('X-Powered-By', '')
        
        if server:
            result['server_info']['server'] = server
            
            # Check for outdated server versions
            if 'Apache/2.2' in server or 'Apache/1.' in server:
                result['vulnerabilities'].append({
                    'name': 'Outdated Web Server',
                    'description': f'Running outdated Apache version: {server}',
                    'severity': 'high',
                    'recommendation': 'Upgrade to the latest Apache version.'
                })
            elif 'nginx/1.0' in server or 'nginx/0.' in server:
                result['vulnerabilities'].append({
                    'name': 'Outdated Web Server',
                    'description': f'Running outdated Nginx version: {server}',
                    'severity': 'high',
                    'recommendation': 'Upgrade to the latest Nginx version.'
                })
        
        if powered_by:
            result['server_info']['powered_by'] = powered_by
            
            # Check for outdated frameworks
            if 'PHP/5.' in powered_by or 'PHP/4.' in powered_by:
                result['vulnerabilities'].append({
                    'name': 'Outdated PHP Version',
                    'description': f'Running outdated PHP version: {powered_by}',
                    'severity': 'high',
                    'recommendation': 'Upgrade to the latest PHP version.'
                })
    
    def _check_common_vulnerabilities(self, response, soup, result):
        """Check for common web vulnerabilities"""
        # Check for forms without CSRF protection
        for i, form in enumerate(result.get('forms', [])):
            if form['method'] == 'POST' and not form['has_csrf_token']:
                result['vulnerabilities'].append({
                    'name': 'Potential CSRF Vulnerability',
                    'description': f'Form #{i+1} with action "{form["action"]}" does not appear to have CSRF protection.',
                    'severity': 'medium',
                    'recommendation': 'Implement CSRF tokens for all forms that modify data.'
                })
        
        # Check for potential XSS vulnerabilities
        if soup:
            # Look for reflected input
            query_params = urllib.parse.parse_qs(urllib.parse.urlparse(response.url).query)
            for param, values in query_params.items():
                for value in values:
                    if value and value in response.text:
                        # Check if the value appears outside of attributes or tags
                        if soup.find(text=re.compile(re.escape(value))):
                            result['vulnerabilities'].append({
                                'name': 'Potential Reflected XSS',
                                'description': f'The parameter "{param}" value is reflected in the page response without proper encoding.',
                                'severity': 'high',
                                'recommendation': 'Implement proper output encoding for user input.'
                            })
                            break
            
            # Dark web checks are now run directly from the scan method
        
        # Check robots.txt for sensitive directories
        try:
            # Construct the robots.txt URL manually based on the domain
            parsed = urllib.parse.urlparse(response.url)
            domain = parsed.netloc
            scheme = parsed.scheme
            robots_url = f"{scheme}://{domain}/robots.txt"
            
            logger.info(f"Checking robots.txt at: {robots_url}")
            
            # Create a direct request for robots.txt instead of using _make_request
            # to avoid recursion issues
            try:
                if self.use_public_proxy and '.onion' in robots_url:
                    logger.info("Skipping robots.txt check for onion sites with public proxy")
                    # Skip robots.txt check for onion sites with public proxy to avoid recursion
                    return  # Skip and return early from the entire method
                else:
                    # For non-onion sites, do a simple request with appropriate timeout
                    robots_response = requests.get(
                        robots_url,
                        proxies=self.tor_proxy if not self.use_public_proxy else None,
                        timeout=2,
                        verify=False
                    )
                    
                    if robots_response.status_code == 200:
                        sensitive_patterns = ['admin', 'login', 'backup', 'wp-admin', 'database', 'config']
                        for pattern in sensitive_patterns:
                            if pattern in robots_response.text.lower():
                                result['vulnerabilities'].append({
                                    'name': 'Sensitive Information in robots.txt',
                                    'description': f'robots.txt contains potentially sensitive path: "{pattern}"',
                                    'severity': 'low',
                                    'recommendation': 'Remove sensitive paths from robots.txt and protect them with proper authentication.'
                                })
            except Exception as e:
                logger.warning(f"Error checking robots.txt: {str(e)}")
                # Ignore robots.txt errors
                pass
        except Exception as e:
            logger.warning(f"Exception in robots.txt check: {str(e)}")
            # Ignore all errors when checking robots.txt
            pass
    
    def _check_darkweb_scam_indicators(self, soup, response, result):
        """Check for common dark web marketplace scam indicators"""
        # Initialize scam score
        scam_score = 0
        scam_indicators = []
        
        # Common scam phrases to check in the website content
        scam_phrases = [
            "guarantee delivery", "100% success rate", "undetectable", 
            "risk-free", "perfect anonymity", "untraceable",
            "no verification needed", "escrow-free", "direct deal",
            "immediate access", "prepayment required", "trust us",
            "money first", "best price on the dark web"
        ]
        
        page_text = soup.get_text().lower()
        for phrase in scam_phrases:
            if phrase.lower() in page_text:
                scam_score += 1
                scam_indicators.append(f"Contains suspicious marketing phrase: '{phrase}'")
        
        # Check for suspicious payment methods
        payment_methods = [
            "western union", "moneygram", "gift card", "direct transfer",
            "irreversible payment", "no escrow", "friends and family",
            "bitcoin only", "no refund"
        ]
        
        for payment in payment_methods:
            if payment.lower() in page_text:
                scam_score += 1
                scam_indicators.append(f"Suspicious payment method: '{payment}'")
        
        # Check for lack of seller verification
        verification_terms = ["pgp", "verification", "signed message", "proof", "escrow service"]
        has_verification = any(term in page_text for term in verification_terms)
        if not has_verification and any(word in page_text for word in ["buy", "purchase", "order"]):
            scam_score += 2
            scam_indicators.append("No seller verification or PGP mentioned")
        
        # Check for unrealistic claims
        unrealistic_claims = [
            "unlimited", "lifetime access", "guaranteed", "100%", 
            "huge discount", "special offer", "exclusive deal",
            "secret method", "hidden technique"
        ]
        
        for claim in unrealistic_claims:
            if claim.lower() in page_text:
                scam_score += 1
                scam_indicators.append(f"Unrealistic claim: '{claim}'")
        
        # Check for fake review patterns
        if soup.find_all(text=re.compile(r'(5\/5|10\/10|100%)')):
            if not soup.find_all(text=re.compile(r'(1\/5|2\/5|3\/5|4\/5)')):
                scam_score += 2
                scam_indicators.append("Only perfect reviews with no negative feedback")
        
        # Add a vulnerability if significant scam indicators were found
        if scam_score >= 3:
            # Prepare a formatted list of indicators
            indicators_formatted = "\n- " + "\n- ".join(scam_indicators[:5])
            if len(scam_indicators) > 5:
                indicators_formatted += f"\n- ...and {len(scam_indicators) - 5} more indicators."
                
            severity = "high" if scam_score > 5 else "medium"
            
            result['vulnerabilities'].append({
                'name': 'Dark Web Marketplace Scam Indicators',
                'description': f'This site shows multiple signs of being a potential scam ({scam_score} indicators detected):{indicators_formatted}',
                'severity': severity,
                'recommendation': 'Exercise extreme caution. Legitimate dark web services typically use escrow payment systems, offer seller verification, and don\'t make unrealistic claims.'
            })
    
    def _check_phishing_indicators(self, soup, response, result):
        """Check for indicators of phishing sites"""
        if not soup:
            return
            
        phishing_score = 0
        phishing_indicators = []
        
        # Extract the page URL and domain
        page_url = response.url
        parsed_url = urllib.parse.urlparse(page_url)
        page_domain = parsed_url.netloc.lower()
        
        # 1. Check for deceptive domain names (misspellings, added hyphens, etc.)
        # List of commonly impersonated services
        common_brands = [
            'paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'google', 
            'facebook', 'instagram', 'twitter', 'linkedin', 'bank', 'account',
            'secure', 'signin', 'login', 'verify', 'wallet', 'blockchain'
        ]
        
        for brand in common_brands:
            # Check for typosquatting (e.g. "paypa1" instead of "paypal")
            if brand in page_domain and any(c.isdigit() for c in page_domain):
                phishing_score += 2
                phishing_indicators.append(f"Potential typosquatting of '{brand}' with numbers")
                break
                
            # Check for excess hyphens (sign of deceptive domains)
            if brand in page_domain and page_domain.count('-') > 1:
                phishing_score += 2
                phishing_indicators.append(f"Suspicious use of multiple hyphens with '{brand}'")
                break
        
        # 2. Check login forms for suspicious attributes
        login_forms = []
        for form in result.get('forms', []):
            # Check if form has password field
            has_password = any(
                input_field.get('type') == 'password' 
                for input_field in form.get('inputs', [])
            )
            if has_password:
                login_forms.append(form)
        
        # Analyze login forms
        for form in login_forms:
            # Check if the form submits to an external domain
            if form.get('action', '').startswith(('http://', 'https://')):
                action_domain = urllib.parse.urlparse(form['action']).netloc
                if action_domain and action_domain != page_domain:
                    phishing_score += 3
                    phishing_indicators.append(f"Login form submits to external domain: {action_domain}")
            
            # Check for suspicious form attributes (hidden fields for credentials)
            suspicious_fields = 0
            for input_field in form.get('inputs', []):
                if input_field.get('type') == 'hidden' and input_field.get('name', '').lower() in ['user', 'username', 'email', 'password']:
                    suspicious_fields += 1
            
            if suspicious_fields > 0:
                phishing_score += 2
                phishing_indicators.append(f"Form contains {suspicious_fields} suspicious hidden fields")
        
        # 3. Check for security-related language to create false sense of security
        security_phrases = [
            'secure login', 'verify your account', 'confirm your identity',
            'account verification', 'security check', 'unusual activity',
            'suspicious login attempt', 'protect your account',
            'limited access', 'account suspended', 'reactivate your account',
            'update your information', 'urgent action required'
        ]
        
        page_text = soup.get_text().lower()
        security_phrases_count = 0
        for phrase in security_phrases:
            if phrase.lower() in page_text:
                security_phrases_count += 1
                
        if security_phrases_count >= 2:
            phishing_score += security_phrases_count
            phishing_indicators.append(f"Contains {security_phrases_count} urgency or security phrases")
        
        # 4. Check for brand logos but mismatched domains
        img_tags = soup.find_all('img')
        for img in img_tags:
            src = img.get('src', '').lower()
            alt = img.get('alt', '').lower()
            
            for brand in common_brands:
                # If image references a known brand but domain doesn't match
                if (brand in src or brand in alt) and brand not in page_domain:
                    phishing_score += 2
                    phishing_indicators.append(f"References '{brand}' brand but domain doesn't match")
                    break
        
        # 5. Check for poor website quality (often indicates phishing)
        # Real sites usually have favicons and proper titles
        has_favicon = soup.find('link', rel=lambda x: x and 'icon' in x.lower()) is not None
        has_title = soup.title is not None and len(soup.title.text.strip()) > 0
        
        if not has_favicon:
            phishing_score += 1
            phishing_indicators.append("No favicon detected")
            
        if not has_title:
            phishing_score += 1
            phishing_indicators.append("No page title detected")
        
        # Always add phishing results if any indicators were found
        # This ensures even low-severity phishing is shown
        if phishing_score >= 1:
            # Format the indicators list
            indicators_formatted = "\n- " + "\n- ".join(phishing_indicators[:5])
            if len(phishing_indicators) > 5:
                indicators_formatted += f"\n- ...and {len(phishing_indicators) - 5} more indicators."
                
            severity = "high" if phishing_score > 6 else "medium" if phishing_score >= 3 else "low"
            
            result['vulnerabilities'].append({
                'name': 'Phishing Site Indicators',
                'description': f'This site exhibits characteristics of a phishing site ({phishing_score} indicators detected):{indicators_formatted}',
                'severity': severity,
                'recommendation': 'Avoid entering any credentials or personal information. Legitimate sites rarely ask for credentials via unusual or unexpected means.'
            })
    
    def _calculate_security_score(self, result):
        """Calculate an overall security score based on vulnerabilities"""
        vulnerabilities = result.get('vulnerabilities', [])
        
        # Count vulnerabilities by severity
        severity_counts = {
            'high': sum(1 for v in vulnerabilities if v.get('severity') == 'high'),
            'medium': sum(1 for v in vulnerabilities if v.get('severity') == 'medium'),
            'low': sum(1 for v in vulnerabilities if v.get('severity') == 'low'),
            'info': sum(1 for v in vulnerabilities if v.get('severity') == 'info')
        }
        
        # Calculate score (100 is best, 0 is worst)
        score = 100
        score -= severity_counts['high'] * 15
        score -= severity_counts['medium'] * 7
        score -= severity_counts['low'] * 3
        
        # Ensure score is within range
        score = max(0, min(100, score))
        
        result['security_score'] = score
        result['severity_counts'] = severity_counts
        
    def _generate_demo_data(self, url):
        """Generate demo data for testing when Tor is not available"""
        logger.info(f"Generating demo data for {url}")
        
        # Create a realistic-looking result structure with demo data
        result = {
            'url': url,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'reachable': True,
            'response_time': 1.25,  # Demo response time
            'status_code': 200,
            'is_demo': True,  # Flag to indicate this is demo data
            'public_proxy_used': False,  # Demo mode doesn't use public proxy
            'server_info': {
                'server': 'Apache/2.4.41 (Unix)',
                'powered_by': 'PHP/7.4.3'
            },
            'vulnerabilities': [
                {
                    'name': 'Phishing Site Indicators',
                    'description': 'This site exhibits characteristics of a phishing site (7 indicators detected):\n- Login form submits to external domain: data-collection.onion\n- Contains 3 urgency or security phrases\n- References \'wallet\' brand but domain doesn\'t match\n- No favicon detected\n- Form contains 1 suspicious hidden fields',
                    'severity': 'high',
                    'recommendation': 'Avoid entering any credentials or personal information. Legitimate sites rarely ask for credentials via unusual or unexpected means.'
                },
                {
                    'name': 'Missing Content-Security-Policy header',
                    'description': 'The Content-Security-Policy header is missing, which could expose the site to various attacks.',
                    'severity': 'medium',
                    'recommendation': 'Add the Content-Security-Policy header to improve security.'
                },
                {
                    'name': 'Cookies without Secure Flag',
                    'description': 'The cookie "session" does not have the Secure flag, allowing transmission over unencrypted connections.',
                    'severity': 'medium',
                    'recommendation': 'Set the Secure flag for all cookies to ensure they are only transmitted over HTTPS.'
                },
                {
                    'name': 'Information Disclosure in HTTP Headers',
                    'description': 'The Server header reveals information about the server technology: Apache/2.4.41 (Unix)',
                    'severity': 'low',
                    'recommendation': 'Remove or obfuscate headers that reveal server technology details.'
                },
                {
                    'name': 'Potential CSRF Vulnerability',
                    'description': 'Form #1 with action "/login" does not appear to have CSRF protection.',
                    'severity': 'high',
                    'recommendation': 'Implement CSRF tokens for all forms that modify data.'
                },
                {
                    'name': 'Outdated JavaScript Library',
                    'description': 'Using jQuery v1.8.3 which has known vulnerabilities.',
                    'severity': 'medium',
                    'recommendation': 'Update to the latest version of jQuery.'
                },
                {
                    'name': 'Dark Web Marketplace Scam Indicators',
                    'description': 'This site shows multiple signs of being a potential scam (6 indicators detected):\n- Contains suspicious marketing phrase: \'guarantee delivery\'\n- Contains suspicious marketing phrase: \'100% success rate\'\n- Suspicious payment method: \'bitcoin only\'\n- No seller verification or PGP mentioned\n- Unrealistic claim: \'guaranteed\'',
                    'severity': 'high',
                    'recommendation': 'Exercise extreme caution. Legitimate dark web services typically use escrow payment systems, offer seller verification, and don\'t make unrealistic claims.'
                }
            ],
            'headers': {
                'Server': 'Apache/2.4.41 (Unix)',
                'X-Powered-By': 'PHP/7.4.3',
                'Content-Type': 'text/html; charset=UTF-8',
                'Cache-Control': 'no-store, no-cache, must-revalidate',
                'X-Frame-Options': 'SAMEORIGIN',
                'X-Content-Type-Options': 'nosniff'
            },
            'cookies': {
                'session': {
                    'value': 'demo_session_value',
                    'secure': False,
                    'httponly': True
                },
                'theme': {
                    'value': 'dark',
                    'secure': False,
                    'httponly': False
                }
            },
            'forms': [
                {
                    'action': '/login',
                    'method': 'POST',
                    'has_csrf_token': False,
                    'inputs': [
                        {'name': 'username', 'type': 'text', 'id': 'username', 'required': True},
                        {'name': 'password', 'type': 'password', 'id': 'password', 'required': True},
                        {'name': 'remember', 'type': 'checkbox', 'id': 'remember', 'required': False}
                    ]
                },
                {
                    'action': '/search',
                    'method': 'GET',
                    'has_csrf_token': False,
                    'inputs': [
                        {'name': 'q', 'type': 'text', 'id': 'search', 'required': True}
                    ]
                }
            ],
            'links': [
                {'url': '/', 'text': 'Home', 'is_internal': True},
                {'url': '/about', 'text': 'About', 'is_internal': True},
                {'url': '/services', 'text': 'Services', 'is_internal': True},
                {'url': '/contact', 'text': 'Contact', 'is_internal': True},
                {'url': 'https://example.com', 'text': 'External Link', 'is_internal': False}
            ]
        }
        
        # Calculate security score based on demo vulnerabilities
        self._calculate_security_score(result)
        
        return result
