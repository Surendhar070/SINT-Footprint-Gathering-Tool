"""
Domain analysis and footprinting module
"""

import socket
import ssl
import requests
import dns.resolver
import dns.exception
from typing import Dict, List, Optional
import json
import re
import logging
import sys
from io import StringIO
import os

# Configure logging BEFORE importing whois to suppress all errors
logging.basicConfig(level=logging.CRITICAL, format='', force=True)

# Completely suppress whois logging at module level - BEFORE IMPORT
_whois_logger = logging.getLogger('whois')
_whois_logger.setLevel(logging.CRITICAL + 1)  # Set above CRITICAL
_whois_logger.disabled = True
_whois_logger.propagate = False  # Prevent propagation to root logger
# Remove all existing handlers
for _handler in list(_whois_logger.handlers):
    _whois_logger.removeHandler(_handler)

# Add custom filter to root logger to block whois messages
class WhoisFilter(logging.Filter):
    def filter(self, record):
        return 'whois' not in record.name.lower()

_root_logger = logging.getLogger()
_root_logger.addFilter(WhoisFilter())

try:
    # Suppress stderr during import to catch any import-time errors
    _old_stderr = sys.stderr
    sys.stderr = StringIO()
    try:
        import whois
        WHOIS_AVAILABLE = True
    finally:
        sys.stderr = _old_stderr
except ImportError:
    WHOIS_AVAILABLE = False


class DomainAnalyzer:
    """Comprehensive domain intelligence gathering"""
    
    def __init__(self):
        self.timeout = 10
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def analyze(self, domain: str) -> Dict:
        """Perform comprehensive domain analysis"""
        result = {
            'domain': domain,
            'dns_records': {},
            'whois': {},
            'subdomains': [],
            'ssl_cert': {},
            'hosting_provider': None,
            'cms_detected': None,
            'technology_stack': [],
            'http_headers': {},
            'registrant_details': {},
            'errors': []
        }
        
        try:
            # DNS Records
            result['dns_records'] = self.get_dns_records(domain)
            
            # WHOIS Data
            result['whois'] = self.get_whois(domain)
            result['registrant_details'] = self.extract_registrant_details(result['whois'])
            
            # SSL Certificate
            result['ssl_cert'] = self.get_ssl_certificate(domain)
            
            # HTTP Headers
            result['http_headers'] = self.get_http_headers(domain)
            
            # Technology Stack
            result['technology_stack'] = self.detect_technology_stack(domain, result['http_headers'])
            
            # CMS Detection
            result['cms_detected'] = self.detect_cms(domain, result['http_headers'])
            
            # Hosting Provider
            result['hosting_provider'] = self.detect_hosting_provider(domain, result['dns_records'])
            
            # Subdomain Enumeration
            result['subdomains'] = self.enumerate_subdomains(domain)
            
        except Exception as e:
            result['errors'].append(str(e))
        
        return result
    
    def get_dns_records(self, domain: str) -> Dict:
        """Get various DNS records"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                records[record_type] = []
            except Exception as e:
                records[record_type] = []
        
        return records
    
    def get_whois(self, domain: str) -> Dict:
        """Get WHOIS information"""
        if not WHOIS_AVAILABLE:
            return {'error': 'WHOIS library not available'}
        
        # Store logger state
        whois_logger = logging.getLogger('whois')
        old_level = whois_logger.level
        old_disabled = whois_logger.disabled
        old_handlers = list(whois_logger.handlers)
        
        # Completely disable whois logger and remove handlers
        whois_logger.setLevel(logging.CRITICAL + 1)  # Set to level above CRITICAL
        whois_logger.disabled = True
        whois_logger.propagate = False  # Prevent propagation to root logger
        # Remove all handlers
        whois_logger.handlers.clear()
        
        # Also suppress root logger propagation
        root_logger = logging.getLogger()
        root_handlers = list(root_logger.handlers)
        
        # Redirect stderr to suppress any console output
        old_stderr = sys.stderr
        old_stdout = sys.stdout
        null_stream = StringIO()
        sys.stderr = null_stream
        sys.stdout = null_stream
        
        try:
            w = whois.whois(domain)
            result = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'dnssec': w.dnssec,
                'raw': str(w) if hasattr(w, '__str__') else None
            }
        except AttributeError:
            # whois library not properly installed
            result = {'error': 'WHOIS lookup unavailable', 'message': 'Library error'}
        except Exception as e:
            # Catch all other errors (network, timeout, etc.) silently
            error_msg = str(e)
            if 'getaddrinfo failed' in error_msg or 'socket' in error_msg.lower() or '11001' in error_msg:
                result = {'error': 'WHOIS server connection failed', 'message': 'Network or DNS issue - WHOIS servers may be unavailable'}
            elif 'PywhoisError' in str(type(e)):
                result = {'error': 'WHOIS lookup failed', 'message': 'Domain WHOIS data not found'}
            else:
                result = {'error': 'WHOIS lookup failed', 'message': 'Unable to retrieve WHOIS data'}
        finally:
            # Always restore everything
            try:
                sys.stderr = old_stderr
                sys.stdout = old_stdout
                whois_logger.disabled = old_disabled
                whois_logger.setLevel(old_level)
                whois_logger.propagate = True
                # Restore handlers
                for handler in old_handlers:
                    whois_logger.addHandler(handler)
            except Exception:
                pass
        
        return result
    
    def extract_registrant_details(self, whois_data: Dict) -> Dict:
        """Extract registrant information from WHOIS"""
        if not whois_data or not isinstance(whois_data, dict):
            return {}
        
        details = {}
        
        domain_name = whois_data.get('domain_name')
        if isinstance(domain_name, list):
            details['domain'] = domain_name[0] if domain_name else None
        else:
            details['domain'] = domain_name
        
        details['registrar'] = whois_data.get('registrar')
        
        # Safely handle emails - ensure it's always a list
        emails = whois_data.get('emails')
        if emails is None:
            details['emails'] = []
        elif isinstance(emails, list):
            details['emails'] = emails
        elif isinstance(emails, str):
            details['emails'] = [emails]
        else:
            details['emails'] = []
        
        # Safely handle name_servers - ensure it's always a list
        name_servers = whois_data.get('name_servers')
        if name_servers is None:
            details['name_servers'] = []
        elif isinstance(name_servers, list):
            details['name_servers'] = name_servers
        elif isinstance(name_servers, str):
            details['name_servers'] = [name_servers]
        else:
            details['name_servers'] = []
        
        return details
    
    def get_ssl_certificate(self, domain: str) -> Dict:
        """Get SSL/TLS certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            # Safely extract certificate info
            subject = {}
            if cert.get('subject'):
                try:
                    subject = dict(x[0] for x in cert['subject'] if x)
                except (TypeError, IndexError):
                    subject = {}
            
            issuer = {}
            if cert.get('issuer'):
                try:
                    issuer = dict(x[0] for x in cert['issuer'] if x)
                except (TypeError, IndexError):
                    issuer = {}
            
            return {
                'subject': subject,
                'issuer': issuer,
                'version': cert.get('version'),
                'serial_number': cert.get('serialNumber'),
                'not_before': cert.get('notBefore'),
                'not_after': cert.get('notAfter')
            }
        except Exception as e:
            return {'error': str(e)}
    
    def get_http_headers(self, domain: str) -> Dict:
        """Get HTTP headers"""
        try:
            url = f"https://{domain}" if not domain.startswith('http') else domain
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            security_headers = {
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                'Referrer-Policy': response.headers.get('Referrer-Policy'),
            }
            
            return {
                'status_code': response.status_code,
                'server': response.headers.get('Server'),
                'x-powered-by': response.headers.get('X-Powered-By'),
                'content_type': response.headers.get('Content-Type'),
                'all_headers': dict(response.headers),
                'security_headers': security_headers
            }
        except Exception as e:
            return {'error': str(e)}
    
    def detect_technology_stack(self, domain: str, headers: Dict) -> List[str]:
        """Detect technology stack from headers and content"""
        stack = []
        
        if headers.get('server'):
            stack.append(f"Server: {headers['server']}")
        
        if headers.get('x-powered-by'):
            stack.append(f"Powered By: {headers['x-powered-by']}")
        
        try:
            url = f"https://{domain}" if not domain.startswith('http') else domain
            response = self.session.get(url, timeout=self.timeout)
            content = response.text.lower()
            
            # Framework detection
            if 'wordpress' in content or '/wp-content/' in content:
                stack.append('WordPress')
            if 'drupal' in content:
                stack.append('Drupal')
            if 'joomla' in content:
                stack.append('Joomla')
            if 'shopify' in content or '.myshopify.com' in content:
                stack.append('Shopify')
            if 'react' in content or 'reactjs' in content:
                stack.append('React')
            if 'angular' in content:
                stack.append('Angular')
            if 'vue' in content:
                stack.append('Vue.js')
            
        except Exception:
            pass
        
        return stack
    
    def detect_cms(self, domain: str, headers: Dict) -> Optional[str]:
        """Detect CMS platform"""
        try:
            url = f"https://{domain}" if not domain.startswith('http') else domain
            response = self.session.get(url, timeout=self.timeout)
            content = response.text.lower()
            
            if '/wp-content/' in content or '/wp-includes/' in content:
                return 'WordPress'
            if '/drupal/' in content or 'drupal' in headers.get('x-powered-by', '').lower():
                return 'Drupal'
            if '/joomla/' in content:
                return 'Joomla'
            if 'shopify' in content or '.myshopify.com' in domain:
                return 'Shopify'
            
            return None
        except Exception:
            return None
    
    def detect_hosting_provider(self, domain: str, dns_records: Dict) -> Optional[str]:
        """Detect hosting provider"""
        if not dns_records or not isinstance(dns_records, dict):
            return None
        
        ns_records = dns_records.get('NS', [])
        if not ns_records or not isinstance(ns_records, list):
            return None
        
        provider_indicators = {
            'AWS': ['amazonaws.com', 'route53'],
            'Cloudflare': ['cloudflare.com', 'cloudflare-dns.com'],
            'Azure': ['azure', 'microsoft.com'],
            'Google Cloud': ['googlecloud', 'googledomains.com'],
            'GoDaddy': ['godaddy.com', 'secureserver.net'],
            'Namecheap': ['namecheap.com'],
        }
        
        for provider, indicators in provider_indicators.items():
            for ns in ns_records:
                if ns and isinstance(ns, str):
                    if any(indicator.lower() in ns.lower() for indicator in indicators):
                        return provider
        
        return None
    
    def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate common subdomains"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'admin', 'blog', 'shop', 'store', 'forum', 'support', 'help', 'dev', 'test',
            'staging', 'api', 'cdn', 'static', 'assets', 'media', 'images', 'img', 'css',
            'js', 'secure', 'login', 'account', 'dashboard', 'portal', 'vpn', 'remote'
        ]
        
        found_subdomains = []
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                found_subdomains.append(full_domain)
            except socket.gaierror:
                continue
        
        return found_subdomains
