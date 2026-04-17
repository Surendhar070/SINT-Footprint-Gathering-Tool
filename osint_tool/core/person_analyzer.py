"""
Person/Username analysis and footprinting module
"""

import requests
import hashlib
from typing import Dict, List, Optional
from urllib.parse import quote


class PersonAnalyzer:
    """Comprehensive person/username intelligence gathering"""
    
    def __init__(self):
        self.timeout = 10
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def analyze(self, username: str) -> Dict:
        """Perform comprehensive person/username analysis"""
        result = {
            'username': username,
            'social_media': [],
            'github_profile': {},
            'email_patterns': [],
            'username_variations': [],
            'forum_profiles': [],
            'cross_platform_links': [],
            'errors': []
        }
        
        try:
            # Social Media Discovery
            result['social_media'] = self.find_social_media_profiles(username)
            
            # GitHub Profile
            result['github_profile'] = self.get_github_profile(username)
            
            # Username Variations
            result['username_variations'] = self.generate_variations(username)
            
            # Email Pattern Generation
            result['email_patterns'] = self.generate_email_patterns(username)
            
            # Forum and Blog Discovery (placeholder)
            result['forum_profiles'] = self.find_forum_profiles(username)
            
            # Cross-platform Identity Links
            result['cross_platform_links'] = self.find_cross_platform_links(username)
            
        except Exception as e:
            result['errors'].append(str(e))
        
        return result
    
    def find_social_media_profiles(self, username: str) -> List[Dict]:
        """Search for username across social media platforms"""
        platforms = [
            {
                'name': 'Twitter/X',
                'url': f'https://twitter.com/{username}',
                'check_url': f'https://twitter.com/{username}'
            },
            {
                'name': 'GitHub',
                'url': f'https://github.com/{username}',
                'check_url': f'https://api.github.com/users/{username}'
            },
            {
                'name': 'Instagram',
                'url': f'https://instagram.com/{username}',
                'check_url': f'https://instagram.com/{username}'
            },
            {
                'name': 'LinkedIn',
                'url': f'https://linkedin.com/in/{username}',
                'check_url': f'https://linkedin.com/in/{username}'
            },
            {
                'name': 'Facebook',
                'url': f'https://facebook.com/{username}',
                'check_url': f'https://facebook.com/{username}'
            },
            {
                'name': 'Reddit',
                'url': f'https://reddit.com/user/{username}',
                'check_url': f'https://reddit.com/user/{username}'
            },
            {
                'name': 'YouTube',
                'url': f'https://youtube.com/@{username}',
                'check_url': f'https://youtube.com/@{username}'
            }
        ]
        
        found_profiles = []
        for platform in platforms:
            exists = self.check_profile_exists(platform['check_url'], platform['name'])
            found_profiles.append({
                'platform': platform['name'],
                'url': platform['url'],
                'exists': exists
            })
        
        return found_profiles
    
    def check_profile_exists(self, url: str, platform: str) -> Optional[bool]:
        """Check if profile exists (basic check)"""
        try:
            if platform == 'GitHub':
                response = self.session.get(url, timeout=self.timeout)
                return response.status_code == 200
            else:
                # For other platforms, just return None (would need proper checking)
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                return response.status_code != 404
        except Exception:
            return None
    
    def get_github_profile(self, username: str) -> Dict:
        """Get GitHub profile information"""
        try:
            url = f"https://api.github.com/users/{username}"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                return {
                    'exists': True,
                    'name': data.get('name'),
                    'bio': data.get('bio'),
                    'company': data.get('company'),
                    'location': data.get('location'),
                    'blog': data.get('blog'),
                    'public_repos': data.get('public_repos'),
                    'followers': data.get('followers'),
                    'following': data.get('following'),
                    'created_at': data.get('created_at'),
                    'avatar_url': data.get('avatar_url')
                }
            else:
                return {'exists': False}
        except Exception as e:
            return {'error': str(e)}
    
    def generate_variations(self, username: str) -> List[str]:
        """Generate username variations"""
        variations = [
            username,
            f"{username}1",
            f"{username}123",
            f"_{username}",
            f"{username}_",
            f"real{username}",
            f"{username}official",
        ]
        return variations
    
    def generate_email_patterns(self, username: str) -> List[str]:
        """Generate potential email patterns"""
        common_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
        patterns = []
        for domain in common_domains:
            patterns.append(f"{username}@{domain}")
        return patterns
    
    def find_forum_profiles(self, username: str) -> List[Dict]:
        """Find forum profiles (placeholder)"""
        # This would require integration with various forum search APIs
        return []
    
    def find_cross_platform_links(self, username: str) -> List[Dict]:
        """Find cross-platform identity links"""
        # This would analyze found profiles to discover links
        return []
