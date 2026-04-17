"""
Threat Intelligence / IOC analysis and footprinting module
"""

import re
import hashlib
import requests
from typing import Dict, List, Optional
from urllib.parse import urlparse


class IOCAnalyzer:
    """Comprehensive threat intelligence and IOC analysis"""
    
    def __init__(self):
        self.timeout = 10
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def analyze(self, ioc: str) -> Dict:
        """Perform comprehensive IOC analysis"""
        ioc_type = self.detect_ioc_type(ioc)
        
        result = {
            'ioc': ioc,
            'ioc_type': ioc_type,
            'malicious_domain_check': {},
            'malicious_ip_check': {},
            'phishing_infrastructure': {},
            'malware_indicators': {},
            'threat_actor_infrastructure': {},
            'c2_relationships': [],
            'classification': {},
            'errors': []
        }
        
        try:
            if ioc_type == 'domain':
                result['malicious_domain_check'] = self.check_malicious_domain(ioc)
                result['phishing_infrastructure'] = self.check_phishing_infrastructure(ioc)
                result['threat_actor_infrastructure'] = self.check_threat_actor_infrastructure(ioc)
                
            elif ioc_type == 'ip':
                result['malicious_ip_check'] = self.check_malicious_ip(ioc)
                result['c2_relationships'] = self.check_c2_relationships(ioc)
                result['threat_actor_infrastructure'] = self.check_threat_actor_infrastructure(ioc)
                
            elif ioc_type == 'url':
                result['malicious_domain_check'] = self.check_malicious_domain(urlparse(ioc).netloc)
                result['phishing_infrastructure'] = self.check_phishing_infrastructure(urlparse(ioc).netloc)
                
            elif ioc_type == 'hash':
                result['malware_indicators'] = self.check_malware_hash(ioc)
                result['classification'] = self.classify_hash(ioc)
                
            result['classification'] = self.classify_ioc(ioc, ioc_type)
            
        except Exception as e:
            result['errors'].append(str(e))
        
        return result
    
    def detect_ioc_type(self, ioc: str) -> str:
        """Detect IOC type"""
        ioc = ioc.strip()
        
        # Hash detection
        if re.match(r'^[a-fA-F0-9]{32}$', ioc):
            return 'hash'  # MD5
        elif re.match(r'^[a-fA-F0-9]{40}$', ioc):
            return 'hash'  # SHA1
        elif re.match(r'^[a-fA-F0-9]{64}$', ioc):
            return 'hash'  # SHA256
        
        # IP detection
        ipv4_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        if ipv4_pattern.match(ioc):
            return 'ip'
        
        # URL detection
        if ioc.startswith(('http://', 'https://')):
            return 'url'
        
        # Domain detection
        domain_pattern = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
        if domain_pattern.match(ioc):
            return 'domain'
        
        return 'unknown'
    
    def check_malicious_domain(self, domain: str) -> Dict:
        """Check if domain is malicious"""
        # Placeholder for API integration (VirusTotal, AbuseIPDB, etc.)
        return {
            'status': 'not_checked',
            'reputation': 'unknown',
            'note': 'Requires API integration (VirusTotal, AbuseIPDB, etc.)',
            'sources': []
        }
    
    def check_malicious_ip(self, ip: str) -> Dict:
        """Check if IP is malicious"""
        # Placeholder for API integration
        return {
            'status': 'not_checked',
            'reputation': 'unknown',
            'abuse_score': None,
            'note': 'Requires API integration (AbuseIPDB, VirusTotal, etc.)',
            'blacklists': []
        }
    
    def check_phishing_infrastructure(self, domain: str) -> Dict:
        """Check for phishing infrastructure"""
        # Placeholder for phishing database integration
        return {
            'is_phishing': 'unknown',
            'suspicious_indicators': [],
            'note': 'Requires phishing database integration'
        }
    
    def check_malware_hash(self, hash_value: str) -> Dict:
        """Check malware hash"""
        hash_type = self.classify_hash(hash_value)
        
        return {
            'hash': hash_value,
            'hash_type': hash_type,
            'is_malicious': 'unknown',
            'malware_family': None,
            'detection_rate': None,
            'note': 'Requires API integration (VirusTotal, Hybrid Analysis, etc.)'
        }
    
    def classify_hash(self, hash_value: str) -> str:
        """Classify hash type"""
        length = len(hash_value)
        if length == 32:
            return 'MD5'
        elif length == 40:
            return 'SHA1'
        elif length == 64:
            return 'SHA256'
        return 'unknown'
    
    def check_threat_actor_infrastructure(self, indicator: str) -> Dict:
        """Check for threat actor infrastructure"""
        return {
            'is_apt': 'unknown',
            'threat_groups': [],
            'note': 'Requires threat intelligence feed integration'
        }
    
    def check_c2_relationships(self, ip: str) -> List[Dict]:
        """Check for C2 (Command and Control) relationships"""
        # Placeholder for C2 infrastructure detection
        return []
    
    def classify_ioc(self, ioc: str, ioc_type: str) -> Dict:
        """Classify IOC"""
        return {
            'type': ioc_type,
            'category': self._get_ioc_category(ioc_type),
            'severity': 'unknown',
            'confidence': 'medium'
        }
    
    def _get_ioc_category(self, ioc_type: str) -> str:
        """Get IOC category"""
        category_map = {
            'ip': 'Network Indicator',
            'domain': 'Network Indicator',
            'url': 'Network Indicator',
            'hash': 'File Indicator',
            'unknown': 'Unknown'
        }
        return category_map.get(ioc_type, 'Unknown')
