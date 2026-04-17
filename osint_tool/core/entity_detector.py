"""
Auto-detection of entity types from input
"""

import re
from enum import Enum
from typing import Optional


class EntityType(Enum):
    MOBILE = "mobile"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    IP = "ip"
    PERSON = "person"
    ORGANIZATION = "organization"
    IOC = "ioc"


class EntityDetector:
    """Automatically detects entity type from input string"""
    
    # Patterns
    MOBILE_PATTERN = re.compile(r'^\+?[\d\s\-\(\)]{7,15}$')
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    IPV4_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    IPV6_PATTERN = re.compile(r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    URL_PATTERN = re.compile(r'^https?://[^\s/$.?#].[^\s]*$', re.IGNORECASE)
    DOMAIN_PATTERN = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    HASH_PATTERN = re.compile(r'^[a-fA-F0-9]{32,64}$')  # MD5, SHA1, SHA256
    
    @staticmethod
    def detect(input_string: str) -> Optional[EntityType]:
        """Detect entity type from input string"""
        input_string = input_string.strip()
        
        # Check URL first (most specific)
        if EntityDetector.URL_PATTERN.match(input_string):
            return EntityType.URL
        
        # Check email
        if EntityDetector.EMAIL_PATTERN.match(input_string):
            return EntityType.EMAIL
        
        # Check IP address
        if EntityDetector.IPV4_PATTERN.match(input_string) or EntityDetector.IPV6_PATTERN.match(input_string):
            return EntityType.IP
        
        # Check hash (IOC)
        if EntityDetector.HASH_PATTERN.match(input_string):
            return EntityType.IOC
        
        # Check domain
        if EntityDetector.DOMAIN_PATTERN.match(input_string):
            return EntityType.DOMAIN
        
        # Check mobile number
        digits_only = re.sub(r'[\s\-\(\)]', '', input_string)
        if EntityDetector.MOBILE_PATTERN.match(input_string) and 7 <= len(digits_only) <= 15:
            return EntityType.MOBILE
        
        # Default to person/username if no match
        return EntityType.PERSON
    
    @staticmethod
    def is_organization(input_string: str) -> bool:
        """Heuristic check if input might be an organization"""
        org_keywords = ['inc', 'llc', 'corp', 'ltd', 'company', 'organization', 'org']
        input_lower = input_string.lower()
        return any(keyword in input_lower for keyword in org_keywords) or \
               (len(input_string.split()) > 1 and not '@' in input_string)
