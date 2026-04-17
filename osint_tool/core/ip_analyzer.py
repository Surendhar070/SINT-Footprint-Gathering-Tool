"""
IP address analysis and footprinting module
"""

import socket
import ipaddress
import requests
import dns.resolver
from typing import Dict, List, Optional
import struct


class IPAnalyzer:
    """Comprehensive IP address intelligence gathering"""
    
    def __init__(self):
        self.timeout = 10
        self.session = requests.Session()
    
    def analyze(self, ip: str) -> Dict:
        """Perform comprehensive IP analysis"""
        result = {
            'ip': ip,
            'geolocation': {},
            'asn_info': {},
            'isp': None,
            'reverse_dns': None,
            'shared_hosting': [],
            'netblock': {},
            'port_scan': {},
            'threat_intelligence': {},
            'is_private': False,
            'is_reserved': False,
            'ip_version': None,
            'errors': []
        }
        
        try:
            # Validate and parse IP
            ip_obj = ipaddress.ip_address(ip)
            result['ip_version'] = 'IPv4' if isinstance(ip_obj, ipaddress.IPv4Address) else 'IPv6'
            result['is_private'] = ip_obj.is_private
            result['is_reserved'] = ip_obj.is_reserved
            
            # Geolocation
            result['geolocation'] = self.get_geolocation(ip)
            
            # ASN Information
            result['asn_info'] = self.get_asn_info(ip)
            
            # ISP Details
            result['isp'] = result['asn_info'].get('org', 'Unknown')
            
            # Reverse DNS
            result['reverse_dns'] = self.get_reverse_dns(ip)
            
            # Netblock Calculation
            result['netblock'] = self.calculate_netblock(ip)
            
            # Shared Hosting Analysis
            result['shared_hosting'] = self.check_shared_hosting(ip)
            
            # Port Scanning (common ports)
            result['port_scan'] = self.scan_common_ports(ip)
            
            # Threat Intelligence (placeholder)
            result['threat_intelligence'] = self.check_threat_intelligence(ip)
            
        except Exception as e:
            result['errors'].append(str(e))
        
        return result
    
    def get_geolocation(self, ip: str) -> Dict:
        """Get geolocation information"""
        try:
            # Using ip-api.com (free tier)
            url = f"http://ip-api.com/json/{ip}"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip': data.get('zip'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as')
                    }
        except Exception as e:
            return {'error': str(e)}
        return {}
    
    def get_asn_info(self, ip: str) -> Dict:
        """Get ASN information"""
        try:
            # Using ip-api.com for ASN
            url = f"http://ip-api.com/json/{ip}"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'as': data.get('as'),
                        'as_number': data.get('as', '').split()[0] if data.get('as') else None,
                        'org': data.get('org'),
                        'isp': data.get('isp')
                    }
        except Exception as e:
            return {'error': str(e)}
        return {}
    
    def get_reverse_dns(self, ip: str) -> Optional[str]:
        """Get reverse DNS (PTR record)"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except socket.herror:
            return None
        except Exception:
            return None
    
    def calculate_netblock(self, ip: str) -> Dict:
        """Calculate IP netblock"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # For IPv4, calculate /24 block
            if isinstance(ip_obj, ipaddress.IPv4Address):
                network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                return {
                    'network': str(network.network_address),
                    'netmask': str(network.netmask),
                    'broadcast': str(network.broadcast_address),
                    'cidr': str(network),
                    'hosts': network.num_addresses
                }
            else:
                # IPv6 /64 block
                network = ipaddress.IPv6Network(f"{ip}/64", strict=False)
                return {
                    'network': str(network.network_address),
                    'netmask': str(network.netmask),
                    'cidr': str(network),
                    'hosts': network.num_addresses
                }
        except Exception as e:
            return {'error': str(e)}
    
    def check_shared_hosting(self, ip: str) -> List[str]:
        """Check for shared hosting (multiple domains on same IP)"""
        # This is a placeholder - actual implementation would require
        # reverse IP lookup services or extensive DNS enumeration
        return []
    
    def scan_common_ports(self, ip: str) -> Dict:
        """Scan common ports"""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Proxy'
        }
        
        open_ports = {}
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports[port] = {
                        'status': 'open',
                        'service': service
                    }
                sock.close()
            except Exception:
                pass
        
        return open_ports
    
    def check_threat_intelligence(self, ip: str) -> Dict:
        """Check threat intelligence feeds (placeholder)"""
        # This would integrate with APIs like:
        # - AbuseIPDB
        # - VirusTotal
        # - AlienVault OTX
        # - Shodan
        return {
            'status': 'not_checked',
            'note': 'Requires API integration'
        }
