"""
URL analysis and footprinting module
"""

import requests
import dns.resolver
from typing import Dict, List, Optional
from urllib.parse import urlparse
import ssl
import socket


class URLAnalyzer:
    """Comprehensive URL intelligence gathering"""
    
    def __init__(self):
        self.timeout = 10
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def analyze(self, url: str) -> Dict:
        """Perform comprehensive URL analysis"""
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        parsed = urlparse(url)
        result = {
            'url': url,
            'domain': parsed.netloc,
            'path': parsed.path,
            'scheme': parsed.scheme,
            'http_headers': {},
            'page_content': {},
            'technology_stack': [],
            'dns_resolution': {},
            'ssl_info': {},
            'robots_txt': None,
            'sitemap': None,
            'security_headers': {},
            'errors': []
        }
        
        try:
            # HTTP Headers
            result['http_headers'] = self.get_http_headers(url)
            result['security_headers'] = self.extract_security_headers(result['http_headers'])
            
            # Page Content
            result['page_content'] = self.analyze_page_content(url)
            
            # Technology Stack
            result['technology_stack'] = self.detect_technology(url, result['http_headers'], result['page_content'])
            
            # DNS Resolution
            result['dns_resolution'] = self.resolve_dns(parsed.netloc)
            
            # SSL Information
            result['ssl_info'] = self.get_ssl_info(parsed.netloc)
            
            # Robots.txt
            result['robots_txt'] = self.get_robots_txt(url)
            
            # Sitemap
            result['sitemap'] = self.get_sitemap(url)
            
        except Exception as e:
            result['errors'].append(str(e))
        
        return result
    
    def get_http_headers(self, url: str) -> Dict:
        """Get HTTP headers"""
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return {
                'status_code': response.status_code,
                'final_url': response.url,
                'redirects': len(response.history),
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'encoding': response.encoding
            }
        except Exception as e:
            return {'error': str(e)}
    
    def extract_security_headers(self, headers_data: Dict) -> Dict:
        """Extract security headers"""
        if 'error' in headers_data:
            return {}
        
        headers = headers_data.get('headers', {})
        return {
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'Referrer-Policy': headers.get('Referrer-Policy'),
            'Permissions-Policy': headers.get('Permissions-Policy'),
        }
    
    def analyze_page_content(self, url: str) -> Dict:
        """Analyze page content"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            content = response.text
            
            # Extract meta tags
            import re
            title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
            title = title_match.group(1).strip() if title_match else None
            
            meta_desc_match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']*)["\']', content, re.IGNORECASE)
            meta_desc = meta_desc_match.group(1) if meta_desc_match else None
            
            meta_keywords_match = re.search(r'<meta\s+name=["\']keywords["\']\s+content=["\']([^"\']*)["\']', content, re.IGNORECASE)
            meta_keywords = meta_keywords_match.group(1) if meta_keywords_match else None
            
            return {
                'title': title,
                'meta_description': meta_desc,
                'meta_keywords': meta_keywords,
                'content_length': len(content),
                'has_forms': '<form' in content.lower(),
                'has_iframes': '<iframe' in content.lower(),
            }
        except Exception as e:
            return {'error': str(e)}
    
    def detect_technology(self, url: str, headers_data: Dict, page_content: Dict) -> List[str]:
        """Detect technology stack"""
        stack = []
        
        if 'error' not in headers_data:
            headers = headers_data.get('headers', {})
            if headers.get('Server'):
                stack.append(f"Server: {headers['Server']}")
            if headers.get('X-Powered-By'):
                stack.append(f"Powered By: {headers['X-Powered-By']}")
        
        if 'error' not in page_content:
            try:
                response = self.session.get(url, timeout=self.timeout)
                content = response.text.lower()
                
                if 'wordpress' in content or '/wp-content/' in content:
                    stack.append('WordPress')
                if 'drupal' in content:
                    stack.append('Drupal')
                if 'react' in content:
                    stack.append('React')
                if 'angular' in content:
                    stack.append('Angular')
                if 'vue' in content:
                    stack.append('Vue.js')
            except Exception:
                pass
        
        return stack
    
    def resolve_dns(self, domain: str) -> Dict:
        """Resolve DNS"""
        try:
            ip = socket.gethostbyname(domain)
            return {
                'ip': ip,
                'resolved': True
            }
        except Exception as e:
            return {
                'resolved': False,
                'error': str(e)
            }
    
    def get_ssl_info(self, domain: str) -> Dict:
        """Get SSL certificate information"""
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
                        'valid_until': cert.get('notAfter'),
                        'valid_from': cert.get('notBefore')
                    }
        except Exception as e:
            return {'error': str(e)}
    
    def get_robots_txt(self, url: str) -> Optional[str]:
        """Get robots.txt content"""
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            response = self.session.get(robots_url, timeout=self.timeout)
            if response.status_code == 200:
                return response.text
        except Exception:
            pass
        return None
    
    def get_sitemap(self, url: str) -> Optional[str]:
        """Get sitemap.xml content"""
        try:
            parsed = urlparse(url)
            sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
            response = self.session.get(sitemap_url, timeout=self.timeout)
            if response.status_code == 200:
                return response.text[:1000]  # First 1000 chars
        except Exception:
            pass
        return None
