"""
Relationship analysis between entities
"""

from typing import Dict, List, Set, Tuple
from collections import defaultdict


class RelationshipAnalyzer:
    """Analyze relationships between entities"""
    
    def __init__(self):
        self.relationships = defaultdict(set)
        self.entity_types = {}
    
    def add_entity(self, entity: str, entity_type: str, analysis_result: Dict):
        """Add an entity and its relationships"""
        self.entity_types[entity] = entity_type
        
        # Extract relationships based on entity type
        if entity_type == 'domain':
            self._extract_domain_relationships(entity, analysis_result)
        elif entity_type == 'email':
            self._extract_email_relationships(entity, analysis_result)
        elif entity_type == 'ip':
            self._extract_ip_relationships(entity, analysis_result)
        elif entity_type == 'person':
            self._extract_person_relationships(entity, analysis_result)
        elif entity_type == 'organization':
            self._extract_organization_relationships(entity, analysis_result)
    
    def _extract_domain_relationships(self, domain: str, result: Dict):
        """Extract relationships from domain analysis"""
        if not result or not isinstance(result, dict):
            return
        
        # DNS records
        dns_records = result.get('dns_records', {})
        if dns_records and isinstance(dns_records, dict):
            for record_type, records in dns_records.items():
                if records and isinstance(records, list):
                    for record in records:
                        if record and isinstance(record, str):
                            self.relationships[domain].add(('dns', record_type, record))
        
        # Subdomains
        subdomains = result.get('subdomains', [])
        if subdomains and isinstance(subdomains, list):
            for subdomain in subdomains:
                if subdomain and isinstance(subdomain, str):
                    self.relationships[domain].add(('subdomain', subdomain))
        
        # WHOIS registrant
        registrant = result.get('registrant_details', {})
        if registrant and isinstance(registrant, dict):
            emails = registrant.get('emails', [])
            if emails and isinstance(emails, list):
                for email in emails:
                    if email and isinstance(email, str):
                        self.relationships[domain].add(('registrant_email', email))
        
        # IP addresses
        if dns_records and isinstance(dns_records, dict):
            a_records = dns_records.get('A', [])
            aaaa_records = dns_records.get('AAAA', [])
            ips = (a_records if isinstance(a_records, list) else []) + (aaaa_records if isinstance(aaaa_records, list) else [])
            for ip in ips:
                if ip and isinstance(ip, str):
                    self.relationships[domain].add(('resolves_to', ip))
    
    def _extract_email_relationships(self, email: str, result: Dict):
        """Extract relationships from email analysis"""
        if not result or not isinstance(result, dict):
            return
        
        domain = result.get('domain')
        if domain and isinstance(domain, str):
            self.relationships[email].add(('email_domain', domain))
        
        # Social profiles
        social_profiles = result.get('social_profiles', [])
        if social_profiles and isinstance(social_profiles, list):
            for profile in social_profiles:
                if profile and isinstance(profile, dict):
                    url = profile.get('url')
                    if url and isinstance(url, str):
                        self.relationships[email].add(('social_profile', url))
        
        # Domain analysis relationships
        domain_analysis = result.get('domain_analysis', {})
        if domain_analysis and isinstance(domain_analysis, dict) and domain:
            self._extract_domain_relationships(domain, domain_analysis)
    
    def _extract_ip_relationships(self, ip: str, result: Dict):
        """Extract relationships from IP analysis"""
        # Reverse DNS
        reverse_dns = result.get('reverse_dns')
        if reverse_dns:
            self.relationships[ip].add(('reverse_dns', reverse_dns))
        
        # Geolocation
        geo = result.get('geolocation', {})
        if geo.get('country'):
            self.relationships[ip].add(('located_in', geo['country']))
        
        # ASN
        asn_info = result.get('asn_info', {})
        if asn_info.get('as'):
            self.relationships[ip].add(('asn', asn_info['as']))
        
        # ISP
        isp = result.get('isp')
        if isp:
            self.relationships[ip].add(('isp', isp))
    
    def _extract_person_relationships(self, username: str, result: Dict):
        """Extract relationships from person analysis"""
        if not result or not isinstance(result, dict):
            return
        
        # Social media profiles
        social_media = result.get('social_media', [])
        if social_media and isinstance(social_media, list):
            for profile in social_media:
                if profile and isinstance(profile, dict):
                    url = profile.get('url')
                    if url and isinstance(url, str):
                        self.relationships[username].add(('social_profile', url))
        
        # GitHub profile
        github = result.get('github_profile', {})
        if github and isinstance(github, dict) and github.get('exists'):
            self.relationships[username].add(('github', f"github.com/{username}"))
        
        # Email patterns
        email_patterns = result.get('email_patterns', [])
        if email_patterns and isinstance(email_patterns, list):
            for email_pattern in email_patterns:
                if email_pattern and isinstance(email_pattern, str):
                    self.relationships[username].add(('potential_email', email_pattern))
    
    def _extract_organization_relationships(self, org: str, result: Dict):
        """Extract relationships from organization analysis"""
        if not result or not isinstance(result, dict):
            return
        
        # Potential domains
        potential_domains = result.get('potential_domains', [])
        if potential_domains and isinstance(potential_domains, list):
            for domain in potential_domains:
                if domain and isinstance(domain, str):
                    self.relationships[org].add(('owns_domain', domain))
        
        # Infrastructure
        infrastructure = result.get('infrastructure', {})
        if infrastructure and isinstance(infrastructure, dict):
            domains = infrastructure.get('domains', [])
            if domains and isinstance(domains, list):
                for domain in domains:
                    if domain and isinstance(domain, str):
                        self.relationships[org].add(('infrastructure_domain', domain))
            ips = infrastructure.get('ips', [])
            if ips and isinstance(ips, list):
                for ip in ips:
                    if ip and isinstance(ip, str):
                        self.relationships[org].add(('infrastructure_ip', ip))
    
    def get_relationships(self, entity: str) -> List[Tuple]:
        """Get all relationships for an entity"""
        return list(self.relationships.get(entity, set()))
    
    def get_relationship_graph(self) -> Dict:
        """Get complete relationship graph"""
        graph = {
            'nodes': [],
            'edges': []
        }
        
        # Add all entities as nodes
        all_entities = set(self.entity_types.keys())
        for entity in all_entities:
            graph['nodes'].append({
                'id': entity,
                'type': self.entity_types.get(entity, 'unknown'),
                'label': entity
            })
        
        # Add relationships as edges
        for entity, relations in self.relationships.items():
            for relation in relations:
                if len(relation) >= 2:
                    relation_type = relation[0]
                    target = relation[1] if len(relation) > 1 else None
                    if target and target in all_entities:
                        graph['edges'].append({
                            'source': entity,
                            'target': target,
                            'type': relation_type,
                            'label': relation_type
                        })
        
        return graph
    
    def find_connections(self, entity1: str, entity2: str, max_depth: int = 3) -> List[List[str]]:
        """Find connection paths between two entities"""
        paths = []
        
        def dfs(current: str, target: str, path: List[str], visited: Set[str], depth: int):
            if depth > max_depth:
                return
            if current == target:
                paths.append(path[:])
                return
            
            visited.add(current)
            for relation in self.relationships.get(current, set()):
                if len(relation) >= 2:
                    next_entity = relation[1]
                    if next_entity not in visited and next_entity in self.entity_types:
                        path.append(next_entity)
                        dfs(next_entity, target, path, visited, depth + 1)
                        path.pop()
            visited.remove(current)
        
        dfs(entity1, entity2, [entity1], set(), 0)
        return paths
    
    def get_related_entities(self, entity: str) -> Dict[str, List[str]]:
        """Get all related entities grouped by relationship type"""
        related = defaultdict(list)
        
        for relation in self.relationships.get(entity, set()):
            if len(relation) >= 2:
                relation_type = relation[0]
                target = relation[1]
                if target in self.entity_types:
                    related[relation_type].append(target)
        
        return dict(related)
