"""
Metasploit Module Database
Comprehensive database of all integrated Metasploit modules with search and categorization
"""

import os
import json
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path

class MetasploitModuleDatabase:
    def __init__(self, modules_path: str = "metasploit_modules"):
        self.modules_path = Path(modules_path)
        self.module_cache = {}
        self.category_map = {
            'auxiliary': 'Auxiliary modules for scanning and enumeration',
            'exploits': 'Exploit modules for gaining unauthorized access',
            'payloads': 'Payload modules for post-exploitation activities',
            'post': 'Post-exploitation modules for information gathering'
        }
        self._build_module_database()
        
    def _build_module_database(self):
        """Build comprehensive module database from Ruby files"""
        for category in ['auxiliary', 'exploits', 'payloads', 'post']:
            category_path = self.modules_path / category
            if category_path.exists():
                self.module_cache[category] = self._scan_category(category_path, category)
                
    def _scan_category(self, category_path: Path, category: str) -> List[Dict]:
        """Scan a category directory for modules"""
        modules = []
        
        for rb_file in category_path.rglob("*.rb"):
            try:
                module_info = self._parse_module_file(rb_file, category)
                if module_info:
                    modules.append(module_info)
            except Exception:
                continue  # Skip problematic files
                
        return modules
        
    def _parse_module_file(self, file_path: Path, category: str) -> Optional[Dict]:
        """Parse a Ruby module file to extract metadata"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Extract module information using regex
            module_info = {
                'path': str(file_path.relative_to(self.modules_path)),
                'category': category,
                'name': self._extract_name(content),
                'description': self._extract_description(content),
                'author': self._extract_author(content),
                'references': self._extract_references(content),
                'targets': self._extract_targets(content),
                'rank': self._extract_rank(content),
                'disclosure_date': self._extract_disclosure_date(content),
                'cve': self._extract_cve(content),
                'platform': self._extract_platform(content),
                'service': self._extract_service(content),
                'options': self._extract_options(content)
            }
            
            return module_info
            
        except Exception:
            return None
            
    def _extract_name(self, content: str) -> str:
        """Extract module name"""
        match = re.search(r"'Name'\s*=>\s*['\"]([^'\"]+)['\"]", content)
        if match:
            return match.group(1)
        
        # Try alternative patterns
        match = re.search(r'"Name"\s*=>\s*[\'"]([^\'"]+)[\'"]', content)
        if match:
            return match.group(1)
            
        return "Unknown Module"
        
    def _extract_description(self, content: str) -> str:
        """Extract module description"""
        match = re.search(r"'Description'\s*=>\s*['\"]([^'\"]+)['\"]", content)
        if match:
            return match.group(1)
            
        match = re.search(r'"Description"\s*=>\s*[\'"]([^\'"]+)[\'"]', content)
        if match:
            return match.group(1)
            
        return "No description available"
        
    def _extract_author(self, content: str) -> List[str]:
        """Extract author information"""
        authors = []
        
        # Look for Author field
        match = re.search(r"'Author'\s*=>\s*\[(.*?)\]", content, re.DOTALL)
        if match:
            author_str = match.group(1)
            # Extract individual author strings
            author_matches = re.findall(r"['\"]([^'\"]+)['\"]", author_str)
            authors.extend(author_matches)
        else:
            # Single author format
            match = re.search(r"'Author'\s*=>\s*['\"]([^'\"]+)['\"]", content)
            if match:
                authors.append(match.group(1))
                
        return authors
        
    def _extract_references(self, content: str) -> List[str]:
        """Extract reference URLs and CVEs"""
        references = []
        
        # Look for References field
        match = re.search(r"'References'\s*=>\s*\[(.*?)\]", content, re.DOTALL)
        if match:
            ref_str = match.group(1)
            # Extract URLs and CVE references
            url_matches = re.findall(r"['\"]([^'\"]*(?:http|cve|CVE)[^'\"]*)['\"]", ref_str)
            references.extend(url_matches)
            
        return references
        
    def _extract_targets(self, content: str) -> List[str]:
        """Extract target platforms"""
        targets = []
        
        match = re.search(r"'Targets'\s*=>\s*\[(.*?)\]", content, re.DOTALL)
        if match:
            target_str = match.group(1)
            target_matches = re.findall(r"['\"]([^'\"]+)['\"]", target_str)
            targets.extend(target_matches)
            
        return targets
        
    def _extract_rank(self, content: str) -> str:
        """Extract exploit rank"""
        match = re.search(r"'Rank'\s*=>\s*(\w+)", content)
        if match:
            return match.group(1)
        return "Unknown"
        
    def _extract_disclosure_date(self, content: str) -> str:
        """Extract disclosure date"""
        match = re.search(r"'DisclosureDate'\s*=>\s*['\"]([^'\"]+)['\"]", content)
        if match:
            return match.group(1)
        return "Unknown"
        
    def _extract_cve(self, content: str) -> List[str]:
        """Extract CVE numbers"""
        cves = re.findall(r"CVE-\d{4}-\d+", content, re.IGNORECASE)
        return list(set(cves))  # Remove duplicates
        
    def _extract_platform(self, content: str) -> List[str]:
        """Extract target platforms"""
        platforms = []
        
        # Common platform indicators
        platform_patterns = [
            r"'Platform'\s*=>\s*['\"]([^'\"]+)['\"]",
            r"windows", r"linux", r"unix", r"osx", r"android", r"java"
        ]
        
        for pattern in platform_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            platforms.extend(matches)
            
        return list(set(platforms))
        
    def _extract_service(self, content: str) -> List[str]:
        """Extract target services"""
        services = []
        
        # Common service indicators
        service_patterns = [
            r"\b(ssh|ftp|telnet|smtp|http|https|smb|mysql|mssql|oracle|rdp|vnc|snmp)\b"
        ]
        
        for pattern in service_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            services.extend(matches)
            
        return list(set(services))
        
    def _extract_options(self, content: str) -> Dict:
        """Extract module options"""
        options = {}
        
        # Look for OptString, OptInt, OptBool patterns
        option_patterns = [
            r"Opt(?:String|Int|Bool|Port|Address)\w*\.new\(['\"]([^'\"]+)['\"]",
            r"register_options\(\[(.*?)\]\)", 
        ]
        
        for pattern in option_patterns:
            matches = re.findall(pattern, content, re.DOTALL)
            for match in matches:
                if isinstance(match, str) and len(match) < 50:
                    options[match] = "configurable"
                    
        return options
        
    def search_modules(self, query: str, category: str = None, 
                      platform: str = None, service: str = None) -> List[Dict]:
        """Search modules by various criteria"""
        results = []
        query_lower = query.lower()
        
        categories_to_search = [category] if category else self.module_cache.keys()
        
        for cat in categories_to_search:
            if cat not in self.module_cache:
                continue
                
            for module in self.module_cache[cat]:
                # Search in name and description
                if (query_lower in module['name'].lower() or 
                    query_lower in module['description'].lower() or
                    query_lower in module['path'].lower()):
                    
                    # Apply additional filters
                    if platform and platform.lower() not in [p.lower() for p in module['platform']]:
                        continue
                        
                    if service and service.lower() not in [s.lower() for s in module['service']]:
                        continue
                        
                    results.append(module)
                    
        return results
        
    def get_modules_by_cve(self, cve: str) -> List[Dict]:
        """Get modules that exploit a specific CVE"""
        results = []
        cve_upper = cve.upper()
        
        for category in self.module_cache:
            for module in self.module_cache[category]:
                if cve_upper in module['cve']:
                    results.append(module)
                    
        return results
        
    def get_modules_by_service(self, service: str) -> List[Dict]:
        """Get modules targeting a specific service"""
        results = []
        service_lower = service.lower()
        
        for category in self.module_cache:
            for module in self.module_cache[category]:
                if service_lower in [s.lower() for s in module['service']]:
                    results.append(module)
                    
        return results
        
    def get_high_rank_exploits(self, limit: int = 50) -> List[Dict]:
        """Get high-ranking exploit modules"""
        high_rank_modules = []
        
        if 'exploits' in self.module_cache:
            for module in self.module_cache['exploits']:
                rank = module['rank'].lower()
                if rank in ['excellent', 'great', 'good']:
                    high_rank_modules.append(module)
                    
        # Sort by rank priority
        rank_priority = {'excellent': 1, 'great': 2, 'good': 3}
        high_rank_modules.sort(key=lambda x: rank_priority.get(x['rank'].lower(), 99))
        
        return high_rank_modules[:limit]
        
    def get_modules_by_platform(self, platform: str) -> List[Dict]:
        """Get modules for a specific platform"""
        results = []
        platform_lower = platform.lower()
        
        for category in self.module_cache:
            for module in self.module_cache[category]:
                if platform_lower in [p.lower() for p in module['platform']]:
                    results.append(module)
                    
        return results
        
    def get_recent_modules(self, year: int = 2020, limit: int = 100) -> List[Dict]:
        """Get recently disclosed modules"""
        recent_modules = []
        
        for category in self.module_cache:
            for module in self.module_cache[category]:
                disclosure_date = module['disclosure_date']
                if disclosure_date != "Unknown" and str(year) in disclosure_date:
                    recent_modules.append(module)
                    
        return recent_modules[:limit]
        
    def export_database(self, filename: str = "metasploit_modules.json"):
        """Export module database to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.module_cache, f, indent=2)
            
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        stats = {
            'total_modules': 0,
            'categories': {},
            'platforms': {},
            'services': {},
            'recent_cves': []
        }
        
        for category in self.module_cache:
            count = len(self.module_cache[category])
            stats['categories'][category] = count
            stats['total_modules'] += count
            
            # Collect platform and service statistics
            for module in self.module_cache[category]:
                for platform in module['platform']:
                    stats['platforms'][platform] = stats['platforms'].get(platform, 0) + 1
                    
                for service in module['service']:
                    stats['services'][service] = stats['services'].get(service, 0) + 1
                    
                # Collect recent CVEs
                for cve in module['cve']:
                    if any(year in cve for year in ['2020', '2021', '2022', '2023', '2024', '2025']):
                        stats['recent_cves'].append(cve)
                        
        # Remove duplicates from recent CVEs
        stats['recent_cves'] = list(set(stats['recent_cves']))
        
        return stats
        
    def recommend_modules_for_target(self, target_info: Dict) -> List[Dict]:
        """Recommend modules based on target information"""
        recommendations = []
        
        # Extract target characteristics
        services = target_info.get('services', [])
        os_type = target_info.get('os', '').lower()
        open_ports = target_info.get('ports', [])
        
        # Find modules for detected services
        for service in services:
            service_modules = self.get_modules_by_service(service)
            recommendations.extend(service_modules[:5])  # Limit per service
            
        # Find modules for the operating system
        if os_type:
            os_modules = self.get_modules_by_platform(os_type)
            recommendations.extend(os_modules[:10])
            
        # Remove duplicates
        seen_paths = set()
        unique_recommendations = []
        for module in recommendations:
            if module['path'] not in seen_paths:
                seen_paths.add(module['path'])
                unique_recommendations.append(module)
                
        return unique_recommendations[:20]  # Limit total recommendations