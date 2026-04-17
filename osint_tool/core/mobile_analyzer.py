"""
Mobile number analysis module
"""

import re
from typing import Dict, Optional
import phonenumbers
from phonenumbers import geocoder, carrier, timezone


class MobileAnalyzer:
    """Mobile number analysis and intelligence gathering"""
    
    # Country code mappings
    COUNTRY_CODES = {
        'US': '+1', 'GB': '+44', 'IN': '+91', 'CN': '+86',
        'DE': '+49', 'FR': '+33', 'JP': '+81', 'BR': '+55',
        'RU': '+7', 'IT': '+39', 'KR': '+82', 'AU': '+61'
    }
    
    def analyze(self, mobile: str) -> Dict:
        """Perform comprehensive mobile number analysis"""
        result = {
            'mobile': mobile,
            'country_code': None,
            'country': None,
            'carrier': None,
            'timezone': [],
            'format_national': None,
            'format_international': None,
            'is_valid': False,
            'number_type': None,
            'errors': []
        }
        
        try:
            # Clean the number
            cleaned = self.clean_number(mobile)
            
            # Try to parse with phonenumbers library
            try:
                # Try different country codes
                parsed = None
                for country, code in self.COUNTRY_CODES.items():
                    try:
                        parsed = phonenumbers.parse(cleaned, country)
                        if phonenumbers.is_valid_number(parsed):
                            break
                    except:
                        continue
                
                if not parsed:
                    # Try without country code
                    parsed = phonenumbers.parse(cleaned, None)
                
                if phonenumbers.is_valid_number(parsed):
                    result['is_valid'] = True
                    result['country_code'] = f"+{parsed.country_code}"
                    result['country'] = geocoder.description_for_number(parsed, "en")
                    result['carrier'] = carrier.name_for_number(parsed, "en") or "Unknown"
                    result['timezone'] = timezone.time_zones_for_number(parsed)
                    result['format_national'] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
                    result['format_international'] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                    result['number_type'] = phonenumbers.number_type(parsed)
                else:
                    result['errors'].append('Invalid phone number format')
                    
            except Exception as e:
                result['errors'].append(f'Parsing error: {str(e)}')
                # Fallback analysis
                result.update(self.basic_analysis(mobile))
        
        except Exception as e:
            result['errors'].append(str(e))
        
        return result
    
    def clean_number(self, mobile: str) -> str:
        """Clean mobile number string"""
        # Remove spaces, dashes, parentheses
        cleaned = re.sub(r'[\s\-\(\)]', '', mobile)
        return cleaned
    
    def basic_analysis(self, mobile: str) -> Dict:
        """Basic analysis without phonenumbers library"""
        cleaned = self.clean_number(mobile)
        
        # Detect country code
        country_code = None
        if cleaned.startswith('+'):
            if cleaned.startswith('+1'):
                country_code = '+1'
            elif cleaned.startswith('+44'):
                country_code = '+44'
            elif cleaned.startswith('+91'):
                country_code = '+91'
        
        return {
            'country_code': country_code,
            'number_length': len(cleaned),
            'has_country_code': cleaned.startswith('+'),
        }
