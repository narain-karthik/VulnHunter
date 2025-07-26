"""
Reconnaissance Phase - Information gathering and target analysis
Handles both passive and active reconnaissance activities
"""

import os
import json
import subprocess
import socket
import requests
from datetime import datetime
from colorama import Fore, Style
from utils.output_formatter import OutputFormatter

class ReconnaissancePhase:
    def __init__(self):
        self.output = OutputFormatter()
        
    def execute_reconnaissance(self, vapt_module, target, session):
        """Execute interactive reconnaissance phase"""
        self.output.print_section_header("INFORMATION GATHERING AND RECONNAISSANCE")
        
        recon_results = {
            'target': target,
            'passive_recon': {},
            'active_recon': {},
            'start_time': datetime.now().isoformat()
        }
        
        # Passive Reconnaissance
        self.output.print_info("Starting Passive Reconnaissance...")
        if self.get_user_confirmation("Passive Reconnaissance"):
            passive_results = self.execute_passive_reconnaissance(vapt_module, target, session)
            recon_results['passive_recon'] = passive_results
            
        # Active Reconnaissance
        self.output.print_info("Starting Active Reconnaissance...")
        if self.get_user_confirmation("Active Reconnaissance"):
            active_results = self.execute_active_reconnaissance(vapt_module, target, session)
            recon_results['active_recon'] = active_results
            
        recon_results['end_time'] = datetime.now().isoformat()
        
        # Save reconnaissance results
        recon_file = os.path.join(session['directory'], 'reconnaissance.json')
        with open(recon_file, 'w') as f:
            json.dump(recon_results, f, indent=2)
            
        session['reconnaissance'] = recon_results
        self.output.print_success("Reconnaissance phase completed successfully!")
        
        return recon_results
        
    def execute_automated_reconnaissance(self, vapt_module, target, session):
        """Execute automated reconnaissance with default settings"""
        self.output.print_info("Executing automated reconnaissance phase...")
        
        recon_results = {
            'target': target,
            'passive_recon': {},
            'active_recon': {},
            'start_time': datetime.now().isoformat()
        }
        
        # Execute both passive and active reconnaissance
        passive_results = self.execute_passive_reconnaissance(vapt_module, target, session)
        recon_results['passive_recon'] = passive_results
        
        active_results = self.execute_active_reconnaissance(vapt_module, target, session)
        recon_results['active_recon'] = active_results
        
        recon_results['end_time'] = datetime.now().isoformat()
        
        # Save reconnaissance results
        recon_file = os.path.join(session['directory'], 'reconnaissance.json')
        with open(recon_file, 'w') as f:
            json.dump(recon_results, f, indent=2)
            
        session['reconnaissance'] = recon_results
        self.output.print_success("Automated reconnaissance phase completed!")
        
        return recon_results
        
    def get_user_confirmation(self, recon_type):
        """Get user confirmation for reconnaissance type"""
        print(f"\n{Fore.YELLOW}Execute {recon_type}?{Style.RESET_ALL}")
        
        if recon_type == "Passive Reconnaissance":
            print("- DNS enumeration and analysis")
            print("- WHOIS information gathering")
            print("- Search engine reconnaissance")
            print("- Social media and public information gathering")
            print("- Certificate transparency logs")
        else:  # Active Reconnaissance
            print("- Port scanning and service enumeration")
            print("- Banner grabbing and service fingerprinting")
            print("- Directory and file enumeration")
            print("- Subdomain and host discovery")
            print("- Network topology mapping")
            
        choice = input(f"{Fore.CYAN}Proceed with {recon_type}? (y/n): {Style.RESET_ALL}").strip().lower()
        return choice in ['y', 'yes']
        
    def execute_passive_reconnaissance(self, vapt_module, target, session):
        """Execute passive reconnaissance activities"""
        self.output.print_info("Executing passive reconnaissance...")
        
        results = {
            'dns_info': {},
            'whois_info': {},
            'search_engine_recon': {},
            'certificate_info': {},
            'subdomain_enum': []
        }
        
        try:
            # DNS Information Gathering
            self.output.print_info("Gathering DNS information...")
            dns_info = self.gather_dns_information(target)
            results['dns_info'] = dns_info
            
            # WHOIS Information
            self.output.print_info("Gathering WHOIS information...")
            whois_info = self.gather_whois_information(target)
            results['whois_info'] = whois_info
            
            # Search Engine Reconnaissance
            self.output.print_info("Performing search engine reconnaissance...")
            search_results = self.perform_search_engine_recon(target)
            results['search_engine_recon'] = search_results
            
            # Certificate Information
            self.output.print_info("Gathering certificate information...")
            cert_info = self.gather_certificate_info(target)
            results['certificate_info'] = cert_info
            
            # Subdomain Enumeration (passive)
            self.output.print_info("Enumerating subdomains (passive)...")
            subdomains = self.enumerate_subdomains_passive(target)
            results['subdomain_enum'] = subdomains
            
        except Exception as e:
            self.output.print_error(f"Error during passive reconnaissance: {str(e)}")
            
        return results
        
    def execute_active_reconnaissance(self, vapt_module, target, session):
        """Execute active reconnaissance activities"""
        self.output.print_info("Executing active reconnaissance...")
        
        results = {
            'port_scan': {},
            'service_enumeration': {},
            'directory_enum': {},
            'subdomain_discovery': {},
            'network_mapping': {}
        }
        
        try:
            # Port Scanning
            self.output.print_info("Performing port scanning...")
            port_scan = self.perform_port_scan(target, vapt_module)
            results['port_scan'] = port_scan
            
            # Service Enumeration
            self.output.print_info("Enumerating services...")
            service_enum = self.enumerate_services(target, port_scan)
            results['service_enumeration'] = service_enum
            
            # Directory/File Enumeration (for web targets)
            if vapt_module.vapt_type in ['web', 'api']:
                self.output.print_info("Enumerating directories and files...")
                dir_enum = self.enumerate_directories(target)
                results['directory_enum'] = dir_enum
                
            # Subdomain Discovery (active)
            self.output.print_info("Discovering subdomains (active)...")
            subdomain_disc = self.discover_subdomains_active(target)
            results['subdomain_discovery'] = subdomain_disc
            
            # Network Mapping
            if vapt_module.vapt_type == 'network':
                self.output.print_info("Mapping network topology...")
                network_map = self.map_network_topology(target)
                results['network_mapping'] = network_map
                
        except Exception as e:
            self.output.print_error(f"Error during active reconnaissance: {str(e)}")
            
        return results
        
    def gather_dns_information(self, target):
        """Gather DNS information for the target"""
        dns_info = {}
        
        try:
            # Extract domain from URL if needed
            domain = self.extract_domain(target)
            
            # Get A records
            try:
                a_records = socket.gethostbyname_ex(domain)
                dns_info['a_records'] = a_records[2]
            except:
                dns_info['a_records'] = []
                
            # Try to get additional DNS info using dig if available
            try:
                dig_output = subprocess.run(['dig', domain, 'ANY'], 
                                          capture_output=True, text=True, timeout=30)
                if dig_output.returncode == 0:
                    dns_info['dig_output'] = dig_output.stdout
            except:
                dns_info['dig_output'] = "dig command not available"
                
        except Exception as e:
            dns_info['error'] = str(e)
            
        return dns_info
        
    def gather_whois_information(self, target):
        """Gather WHOIS information for the target"""
        whois_info = {}
        
        try:
            domain = self.extract_domain(target)
            
            # Try to get WHOIS info using whois command
            try:
                whois_output = subprocess.run(['whois', domain], 
                                            capture_output=True, text=True, timeout=30)
                if whois_output.returncode == 0:
                    whois_info['whois_data'] = whois_output.stdout
                else:
                    whois_info['error'] = whois_output.stderr
            except:
                whois_info['error'] = "whois command not available"
                
        except Exception as e:
            whois_info['error'] = str(e)
            
        return whois_info
        
    def perform_search_engine_recon(self, target):
        """Perform search engine reconnaissance"""
        search_results = {
            'google_dorks': [],
            'bing_searches': [],
            'general_info': []
        }
        
        # This would typically involve automated searches
        # For now, we'll provide suggested search queries
        domain = self.extract_domain(target)
        
        search_results['suggested_google_dorks'] = [
            f'site:{domain}',
            f'site:{domain} filetype:pdf',
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:config',
            f'site:{domain} "index of"'
        ]
        
        return search_results
        
    def gather_certificate_info(self, target):
        """Gather SSL/TLS certificate information"""
        cert_info = {}
        
        try:
            domain = self.extract_domain(target)
            
            # Try to get certificate info using openssl
            try:
                ssl_output = subprocess.run([
                    'openssl', 's_client', '-connect', f'{domain}:443', '-servername', domain
                ], input='', capture_output=True, text=True, timeout=10)
                
                if ssl_output.returncode == 0:
                    cert_info['ssl_info'] = ssl_output.stdout
                else:
                    cert_info['error'] = "Could not retrieve SSL certificate"
            except:
                cert_info['error'] = "openssl command not available"
                
        except Exception as e:
            cert_info['error'] = str(e)
            
        return cert_info
        
    def enumerate_subdomains_passive(self, target):
        """Enumerate subdomains using passive methods"""
        subdomains = []
        
        try:
            domain = self.extract_domain(target)
            
            # Common subdomain list
            common_subdomains = [
                'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'dev', 'test',
                'staging', 'secure', 'vpn', 'remote', 'portal', 'app'
            ]
            
            for subdomain in common_subdomains:
                full_subdomain = f"{subdomain}.{domain}"
                try:
                    socket.gethostbyname(full_subdomain)
                    subdomains.append(full_subdomain)
                except:
                    pass
                    
        except Exception as e:
            pass
            
        return subdomains
        
    def perform_port_scan(self, target, vapt_module):
        """Perform port scanning on the target"""
        port_scan_results = {}
        
        try:
            # Extract IP or domain
            hostname = self.extract_hostname(target)
            
            # Try using nmap if available
            try:
                nmap_cmd = ['nmap', '-sS', '-O', '-sV', '--top-ports', '1000', hostname]
                nmap_output = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=300)
                
                if nmap_output.returncode == 0:
                    port_scan_results['nmap_output'] = nmap_output.stdout
                    port_scan_results['open_ports'] = self.parse_nmap_output(nmap_output.stdout)
                else:
                    port_scan_results['error'] = nmap_output.stderr
            except:
                # Fallback to basic port scanning
                port_scan_results = self.basic_port_scan(hostname)
                
        except Exception as e:
            port_scan_results['error'] = str(e)
            
        return port_scan_results
        
    def basic_port_scan(self, hostname):
        """Basic port scanning without nmap"""
        results = {'open_ports': []}
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    results['open_ports'].append({'port': port, 'state': 'open'})
                sock.close()
            except:
                pass
                
        return results
        
    def parse_nmap_output(self, nmap_output):
        """Parse nmap output to extract open ports"""
        open_ports = []
        lines = nmap_output.split('\n')
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = {
                        'port': parts[0].split('/')[0],
                        'state': parts[1],
                        'service': parts[2] if len(parts) > 2 else 'unknown'
                    }
                    open_ports.append(port_info)
                    
        return open_ports
        
    def enumerate_services(self, target, port_scan):
        """Enumerate services on open ports"""
        services = {}
        
        try:
            if 'open_ports' in port_scan:
                for port_info in port_scan['open_ports']:
                    port = port_info.get('port', '')
                    if port:
                        service_info = self.probe_service(target, int(port))
                        services[port] = service_info
        except Exception as e:
            services['error'] = str(e)
            
        return services
        
    def probe_service(self, target, port):
        """Probe a specific service on a port"""
        service_info = {'port': port, 'banner': '', 'service_type': 'unknown'}
        
        try:
            hostname = self.extract_hostname(target)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((hostname, port))
            
            # Try to get banner
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                service_info['banner'] = banner
                service_info['service_type'] = self.identify_service_type(port, banner)
            except:
                pass
                
            sock.close()
        except Exception as e:
            service_info['error'] = str(e)
            
        return service_info
        
    def identify_service_type(self, port, banner):
        """Identify service type based on port and banner"""
        port_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL'
        }
        
        service_type = port_services.get(port, 'Unknown')
        
        # Enhance based on banner
        if banner:
            banner_lower = banner.lower()
            if 'http' in banner_lower:
                service_type = 'HTTP'
            elif 'ssh' in banner_lower:
                service_type = 'SSH'
            elif 'ftp' in banner_lower:
                service_type = 'FTP'
                
        return service_type
        
    def enumerate_directories(self, target):
        """Enumerate directories and files for web targets"""
        dir_enum = {}
        
        try:
            # Try using gobuster if available
            try:
                gobuster_cmd = ['gobuster', 'dir', '-u', target, '-w', '/usr/share/wordlists/dirb/common.txt', '-q']
                gobuster_output = subprocess.run(gobuster_cmd, capture_output=True, text=True, timeout=300)
                
                if gobuster_output.returncode == 0:
                    dir_enum['gobuster_output'] = gobuster_output.stdout
                    dir_enum['directories'] = self.parse_gobuster_output(gobuster_output.stdout)
                else:
                    # Fallback to basic directory enumeration
                    dir_enum = self.basic_directory_enum(target)
            except:
                # Fallback to basic directory enumeration
                dir_enum = self.basic_directory_enum(target)
                
        except Exception as e:
            dir_enum['error'] = str(e)
            
        return dir_enum
        
    def basic_directory_enum(self, target):
        """Basic directory enumeration without gobuster"""
        results = {'directories': []}
        common_dirs = [
            'admin', 'administrator', 'login', 'api', 'test', 'dev',
            'backup', 'config', 'uploads', 'images', 'css', 'js'
        ]
        
        for directory in common_dirs:
            try:
                url = f"{target.rstrip('/')}/{directory}"
                response = requests.get(url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    results['directories'].append({
                        'path': f"/{directory}",
                        'status': response.status_code
                    })
            except:
                pass
                
        return results
        
    def parse_gobuster_output(self, gobuster_output):
        """Parse gobuster output to extract directories"""
        directories = []
        lines = gobuster_output.split('\n')
        
        for line in lines:
            if line.strip() and not line.startswith('='):
                parts = line.split()
                if len(parts) >= 2:
                    directories.append({
                        'path': parts[0],
                        'status': parts[1] if parts[1].isdigit() else 'unknown'
                    })
                    
        return directories
        
    def discover_subdomains_active(self, target):
        """Discover subdomains using active methods"""
        subdomains = []
        
        try:
            domain = self.extract_domain(target)
            
            # Try using subfinder if available
            try:
                subfinder_cmd = ['subfinder', '-d', domain, '-silent']
                subfinder_output = subprocess.run(subfinder_cmd, capture_output=True, text=True, timeout=60)
                
                if subfinder_output.returncode == 0:
                    subdomains = subfinder_output.stdout.strip().split('\n')
                    subdomains = [sub.strip() for sub in subdomains if sub.strip()]
            except:
                # Fallback to DNS brute force
                subdomains = self.dns_brute_force(domain)
                
        except Exception as e:
            pass
            
        return subdomains
        
    def dns_brute_force(self, domain):
        """DNS brute force for subdomain discovery"""
        subdomains = []
        wordlist = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'app', 'secure', 'vpn', 'portal', 'blog', 'shop'
        ]
        
        for word in wordlist:
            subdomain = f"{word}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.append(subdomain)
            except:
                pass
                
        return subdomains
        
    def map_network_topology(self, target):
        """Map network topology for network targets"""
        network_map = {}
        
        try:
            # Try using traceroute if available
            try:
                hostname = self.extract_hostname(target)
                traceroute_cmd = ['traceroute', hostname]
                traceroute_output = subprocess.run(traceroute_cmd, capture_output=True, text=True, timeout=60)
                
                if traceroute_output.returncode == 0:
                    network_map['traceroute'] = traceroute_output.stdout
            except:
                network_map['traceroute'] = "traceroute command not available"
                
        except Exception as e:
            network_map['error'] = str(e)
            
        return network_map
        
    def extract_domain(self, target):
        """Extract domain from target (handles URLs and IPs)"""
        if target.startswith('http'):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            return parsed.netloc
        elif '/' in target and not target.replace('.', '').replace('/', '').isdigit():
            return target.split('/')[0]
        else:
            return target
            
    def extract_hostname(self, target):
        """Extract hostname/IP from target"""
        if target.startswith('http'):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            return parsed.netloc.split(':')[0]
        elif '/' in target:
            return target.split('/')[0]
        else:
            return target.split(':')[0]
