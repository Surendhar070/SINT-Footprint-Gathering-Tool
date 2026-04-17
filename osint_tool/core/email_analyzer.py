"""
Email analysis and footprinting module
"""

import dns.resolver
import hashlib
import requests
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse


class EmailAnalyzer:
    """Comprehensive email intelligence gathering"""
    
    def __init__(self):
        self.timeout = 10
        self.session = requests.Session()
        self.disposable_domains = [
            'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com'
        ]
    
    def analyze(self, email: str) -> Dict:
        """Perform comprehensive email analysis"""
        local_part, domain = email.split('@') if '@' in email else (None, None)
        
        result = {
            'email': email,
            'local_part': local_part,
            'domain': domain,
            'domain_analysis': {},
            'mx_records': [],
            'email_security': {},
            'email_format': {},
            'is_disposable': False,
            'is_role_based': False,
            'gravatar_hash': None,
            'gravatar_profile': None,
            'is_valid': False,
            'social_profiles': [],
            'errors': []
        }
        
        try:
            if not domain:
                result['errors'].append('Invalid email format')
                return result
            
            result['is_valid'] = self.validate_email(email)
            
            # Domain Analysis
            from .domain_analyzer import DomainAnalyzer
            domain_analyzer = DomainAnalyzer()
            result['domain_analysis'] = domain_analyzer.analyze(domain)
            
            # MX Records
            result['mx_records'] = self.get_mx_records(domain)
            
            # Email Security (SPF, DKIM, DMARC)
            result['email_security'] = self.get_email_security(domain)
            
            # Email Format Analysis
            result['email_format'] = self.analyze_email_format(local_part)
            
            # Disposable Email Detection
            result['is_disposable'] = self.is_disposable_email(domain)
            
            # Role-based Detection
            result['is_role_based'] = self.is_role_based_email(local_part)
            
            # Gravatar
            result['gravatar_hash'] = self.calculate_gravatar_hash(email)
            result['gravatar_profile'] = self.get_gravatar_profile(result['gravatar_hash'])
            
            # Social Profile Associations
            result['social_profiles'] = self.find_social_profiles(email, local_part)
            
        except Exception as e:
            result['errors'].append(str(e))
        
        return result
    
    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return bool(pattern.match(email))
    
    def get_mx_records(self, domain: str) -> List[Dict]:
        """Get MX records for email domain"""
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = []
            for rdata in answers:
                mx_records.append({
                    'priority': rdata.preference,
                    'exchange': str(rdata.exchange)
                })
            return sorted(mx_records, key=lambda x: x['priority'])
        except Exception as e:
            return []
    
    def get_email_security(self, domain: str) -> Dict:
        """Get SPF, DKIM, DMARC records"""
        security = {
            'spf': None,
            'dkim': None,
            'dmarc': None
        }
        
        try:
            # SPF (usually in TXT records)
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for rdata in txt_records:
                if rdata and hasattr(rdata, 'strings') and rdata.strings:
                    try:
                        txt_string = ''.join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings if s])
                        if txt_string.startswith('v=spf1'):
                            security['spf'] = txt_string
                        if txt_string.startswith('v=DMARC1'):
                            security['dmarc'] = txt_string
                    except (AttributeError, TypeError):
                        continue
            
            # DMARC (specific record)
            try:
                dmarc_domain = f'_dmarc.{domain}'
                dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
                for rdata in dmarc_records:
                    if rdata and hasattr(rdata, 'strings') and rdata.strings:
                        try:
                            txt_string = ''.join([s.decode() if isinstance(s, bytes) else str(s) for s in rdata.strings if s])
                            if txt_string.startswith('v=DMARC1'):
                                security['dmarc'] = txt_string
                        except (AttributeError, TypeError):
                            continue
            except Exception:
                pass
            
        except Exception:
            pass
        
        return security
    
    def analyze_email_format(self, local_part: str) -> Dict:
        """Analyze email format patterns"""
        if not local_part:
            return {}
        
        format_info = {
            'has_dots': '.' in local_part,
            'has_plus': '+' in local_part,
            'has_digits': bool(re.search(r'\d', local_part)),
            'has_underscores': '_' in local_part,
            'length': len(local_part),
            'is_numeric': local_part.isdigit(),
            'pattern': self.detect_pattern(local_part)
        }
        
        return format_info
    
    def detect_pattern(self, local_part: str) -> str:
        """Detect common email patterns"""
        if re.match(r'^[a-z]+\.[a-z]+$', local_part.lower()):
            return 'firstname.lastname'
        elif re.match(r'^[a-z]+[0-9]+$', local_part.lower()):
            return 'name_number'
        elif re.match(r'^[a-z]+\d*$', local_part.lower()):
            return 'simple_name'
        else:
            return 'custom'
    
    def is_disposable_email(self, domain: str) -> bool:
        """Check if domain is a disposable email service"""
        return domain.lower() in [d.lower() for d in self.disposable_domains]
    
    def is_role_based_email(self, local_part: str) -> bool:
        """Check if email is role-based"""
        role_keywords = ['admin', 'administrator', 'support', 'help', 'info', 'contact',
                        'noreply', 'no-reply', 'postmaster', 'abuse', 'security', 'sales']
        return local_part.lower() in role_keywords if local_part else False
    
    def calculate_gravatar_hash(self, email: str) -> str:
        """Calculate MD5 hash for Gravatar"""
        email_lower = email.lower().strip()
        return hashlib.md5(email_lower.encode()).hexdigest()
    
    def get_gravatar_profile(self, gravatar_hash: str) -> Optional[Dict]:
        """Get Gravatar profile information"""
        try:
            url = f"https://www.gravatar.com/{gravatar_hash}.json"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return None
    
    def find_social_profiles(self, email: str, username: str) -> List[Dict]:
        """Find potential social media profiles"""
        profiles = []
        
        # Common platforms to check
        platforms = {
            'GitHub': f"https://github.com/{username}",
            'Twitter': f"https://twitter.com/{username}",
        }
        
        # Note: Actual profile discovery would require API calls or scraping
        # This is a placeholder structure
        for platform, url in platforms.items():
            profiles.append({
                'platform': platform,
                'url': url,
                'exists': None  # Would require actual checking
            })
        
        return profiles
