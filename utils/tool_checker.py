"""
Tool Checker - Verify availability and functionality of security tools
Handles checking for required security tools and their proper installation
"""

import subprocess
import os
import json
import time
from colorama import Fore, Style

class ToolChecker:
    def __init__(self):
        self.config_file = os.path.join(os.path.dirname(__file__), '..', 'config', 'tools.json')
        self.load_tool_configuration()
        
    def load_tool_configuration(self):
        """Load tool configuration from JSON file"""
        try:
            with open(self.config_file, 'r') as f:
                self.tools_config = json.load(f)
        except FileNotFoundError:
            # Default configuration if file doesn't exist
            self.tools_config = self.get_default_tool_configuration()
            
    def get_default_tool_configuration(self):
        """Get default tool configuration"""
        return {
            "critical_tools": {
                "nmap": {
                    "description": "Network discovery and security auditing",
                    "check_command": ["nmap", "--version"],
                    "install_hint": "sudo apt-get install nmap"
                },
                "curl": {
                    "description": "HTTP client for API testing",
                    "check_command": ["curl", "--version"],
                    "install_hint": "sudo apt-get install curl"
                },
                "python3": {
                    "description": "Python interpreter",
                    "check_command": ["python3", "--version"],
                    "install_hint": "sudo apt-get install python3"
                }
            },
            "network_tools": {
                "nmap": {
                    "description": "Network discovery and port scanning",
                    "check_command": ["nmap", "--version"],
                    "install_hint": "sudo apt-get install nmap"
                },
                "masscan": {
                    "description": "High-speed port scanner",
                    "check_command": ["masscan", "--version"],
                    "install_hint": "sudo apt-get install masscan"
                },
                "netdiscover": {
                    "description": "Network host discovery",
                    "check_command": ["netdiscover", "-h"],
                    "install_hint": "sudo apt-get install netdiscover"
                },
                "arp-scan": {
                    "description": "ARP-based host discovery",
                    "check_command": ["arp-scan", "--version"],
                    "install_hint": "sudo apt-get install arp-scan"
                },
                "fping": {
                    "description": "Fast ping sweep utility",
                    "check_command": ["fping", "-v"],
                    "install_hint": "sudo apt-get install fping"
                },
                "hping3": {
                    "description": "Custom packet crafting tool",
                    "check_command": ["hping3", "--version"],
                    "install_hint": "sudo apt-get install hping3"
                },
                "traceroute": {
                    "description": "Network path discovery",
                    "check_command": ["traceroute", "--version"],
                    "install_hint": "sudo apt-get install traceroute"
                },
                "enum4linux": {
                    "description": "SMB enumeration tool",
                    "check_command": ["enum4linux", "-h"],
                    "install_hint": "sudo apt-get install enum4linux"
                },
                "snmpwalk": {
                    "description": "SNMP enumeration tool",
                    "check_command": ["snmpwalk", "--version"],
                    "install_hint": "sudo apt-get install snmp"
                }
            },
            "web_tools": {
                "nikto": {
                    "description": "Web server vulnerability scanner",
                    "check_command": ["nikto", "-Version"],
                    "install_hint": "sudo apt-get install nikto"
                },
                "dirb": {
                    "description": "Web directory brute forcer",
                    "check_command": ["dirb"],
                    "install_hint": "sudo apt-get install dirb"
                },
                "gobuster": {
                    "description": "Fast directory/file enumeration tool",
                    "check_command": ["gobuster", "version"],
                    "install_hint": "sudo apt-get install gobuster"
                },
                "sqlmap": {
                    "description": "SQL injection testing tool",
                    "check_command": ["sqlmap", "--version"],
                    "install_hint": "sudo apt-get install sqlmap"
                },
                "wfuzz": {
                    "description": "Web application fuzzer",
                    "check_command": ["wfuzz", "--version"],
                    "install_hint": "pip3 install wfuzz"
                },
                "ffuf": {
                    "description": "Fast web fuzzer",
                    "check_command": ["ffuf", "-V"],
                    "install_hint": "go install github.com/ffuf/ffuf@latest"
                },
                "whatweb": {
                    "description": "Web technology fingerprinting",
                    "check_command": ["whatweb", "--version"],
                    "install_hint": "sudo apt-get install whatweb"
                },
                "wafw00f": {
                    "description": "Web application firewall detection",
                    "check_command": ["wafw00f", "--version"],
                    "install_hint": "pip3 install wafw00f"
                }
            },
            "ssl_tools": {
                "sslscan": {
                    "description": "SSL/TLS configuration scanner",
                    "check_command": ["sslscan", "--version"],
                    "install_hint": "sudo apt-get install sslscan"
                },
                "testssl.sh": {
                    "description": "SSL/TLS security testing",
                    "check_command": ["testssl.sh", "--version"],
                    "install_hint": "git clone https://github.com/drwetter/testssl.sh.git"
                },
                "openssl": {
                    "description": "SSL/TLS toolkit",
                    "check_command": ["openssl", "version"],
                    "install_hint": "sudo apt-get install openssl"
                }
            },
            "api_tools": {
                "curl": {
                    "description": "HTTP client for API testing",
                    "check_command": ["curl", "--version"],
                    "install_hint": "sudo apt-get install curl"
                },
                "jq": {
                    "description": "JSON processor",
                    "check_command": ["jq", "--version"],
                    "install_hint": "sudo apt-get install jq"
                }
            },
            "cloud_tools": {
                "aws": {
                    "description": "AWS CLI",
                    "check_command": ["aws", "--version"],
                    "install_hint": "pip3 install awscli"
                },
                "azure": {
                    "description": "Azure CLI",
                    "check_command": ["az", "--version"],
                    "install_hint": "curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash"
                },
                "gcloud": {
                    "description": "Google Cloud CLI",
                    "check_command": ["gcloud", "version"],
                    "install_hint": "Install Google Cloud SDK"
                }
            },
            "general_tools": {
                "git": {
                    "description": "Version control system",
                    "check_command": ["git", "--version"],
                    "install_hint": "sudo apt-get install git"
                },
                "wget": {
                    "description": "Web file retrieval",
                    "check_command": ["wget", "--version"],
                    "install_hint": "sudo apt-get install wget"
                },
                "whois": {
                    "description": "Domain registration lookup",
                    "check_command": ["whois", "--version"],
                    "install_hint": "sudo apt-get install whois"
                },
                "dig": {
                    "description": "DNS lookup utility",
                    "check_command": ["dig", "-v"],
                    "install_hint": "sudo apt-get install dnsutils"
                }
            }
        }
        
    def check_tool_availability(self, tool_name, tool_config):
        """Check if a specific tool is available and working"""
        try:
            result = subprocess.run(
                tool_config['check_command'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Most tools return 0 for version checks, but some may return 1
            if result.returncode in [0, 1]:
                return {
                    'available': True,
                    'version': self.extract_version(result.stdout + result.stderr),
                    'status': 'OK'
                }
            else:
                return {
                    'available': False,
                    'error': result.stderr.strip() if result.stderr else 'Unknown error',
                    'status': 'ERROR'
                }
                
        except subprocess.TimeoutExpired:
            return {
                'available': False,
                'error': 'Command timeout',
                'status': 'TIMEOUT'
            }
        except FileNotFoundError:
            return {
                'available': False,
                'error': 'Command not found',
                'status': 'NOT_FOUND'
            }
        except Exception as e:
            return {
                'available': False,
                'error': str(e),
                'status': 'ERROR'
            }
            
    def extract_version(self, output):
        """Extract version information from command output"""
        import re
        
        # Common version patterns
        patterns = [
            r'version\s+(\d+(?:\.\d+)*)',
            r'v(\d+(?:\.\d+)*)',
            r'(\d+(?:\.\d+)+)',
            r'Version:\s*(\d+(?:\.\d+)*)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return "Unknown"
        
    def check_critical_tools(self):
        """Check availability of critical tools"""
        print(f"{Fore.CYAN}Checking critical tools...{Style.RESET_ALL}\n")
        
        critical_tools = self.tools_config.get('critical_tools', {})
        all_available = True
        
        for tool_name, tool_config in critical_tools.items():
            result = self.check_tool_availability(tool_name, tool_config)
            
            if result['available']:
                print(f"  ✓ {Fore.GREEN}{tool_name}{Style.RESET_ALL} - {tool_config['description']}")
                if 'version' in result:
                    print(f"    Version: {result['version']}")
            else:
                print(f"  ✗ {Fore.RED}{tool_name}{Style.RESET_ALL} - {tool_config['description']}")
                print(f"    Error: {result['error']}")
                print(f"    Install: {tool_config.get('install_hint', 'No installation hint available')}")
                all_available = False
                
            print()
            
        return all_available
        
    def check_category_tools(self, category):
        """Check tools in a specific category"""
        print(f"{Fore.CYAN}Checking {category} tools...{Style.RESET_ALL}\n")
        
        category_tools = self.tools_config.get(category, {})
        results = {}
        
        for tool_name, tool_config in category_tools.items():
            result = self.check_tool_availability(tool_name, tool_config)
            results[tool_name] = result
            
            if result['available']:
                print(f"  ✓ {Fore.GREEN}{tool_name}{Style.RESET_ALL} - {tool_config['description']}")
                if 'version' in result:
                    print(f"    Version: {result['version']}")
            else:
                print(f"  ✗ {Fore.RED}{tool_name}{Style.RESET_ALL} - {tool_config['description']}")
                print(f"    Error: {result['error']}")
                print(f"    Install: {tool_config.get('install_hint', 'No installation hint available')}")
                
            print()
            
        return results
        
    def check_all_dependencies(self):
        """Check all tool dependencies"""
        print(f"{Fore.CYAN}VAPT TOOL DEPENDENCY CHECK{Style.RESET_ALL}")
        print("="*50)
        print()
        
        # Check critical tools first
        critical_ok = self.check_critical_tools()
        
        if not critical_ok:
            print(f"{Fore.RED}⚠️  Critical tools missing! Some functionality may not work.{Style.RESET_ALL}\n")
            
        # Check category-specific tools
        categories = ['network_tools', 'web_tools', 'ssl_tools', 'api_tools', 'cloud_tools', 'general_tools']
        
        for category in categories:
            if category in self.tools_config:
                self.check_category_tools(category)
                
        # Summary
        print(f"{Fore.CYAN}DEPENDENCY CHECK SUMMARY{Style.RESET_ALL}")
        print("-"*30)
        
        total_tools = 0
        available_tools = 0
        
        for category, tools in self.tools_config.items():
            for tool_name, tool_config in tools.items():
                total_tools += 1
                result = self.check_tool_availability(tool_name, tool_config)
                if result['available']:
                    available_tools += 1
                    
        print(f"Available tools: {available_tools}/{total_tools}")
        coverage = (available_tools / total_tools) * 100 if total_tools > 0 else 0
        
        if coverage >= 90:
            print(f"Coverage: {Fore.GREEN}{coverage:.1f}%{Style.RESET_ALL} - Excellent")
        elif coverage >= 70:
            print(f"Coverage: {Fore.YELLOW}{coverage:.1f}%{Style.RESET_ALL} - Good")
        else:
            print(f"Coverage: {Fore.RED}{coverage:.1f}%{Style.RESET_ALL} - Poor")
            
        print()
        
        if coverage < 70:
            print(f"{Fore.YELLOW}💡 Consider installing missing tools for full functionality{Style.RESET_ALL}")
            
        return critical_ok
        
    def get_tool_installation_script(self):
        """Generate an installation script for missing tools"""
        script_lines = ["#!/bin/bash", "# VAPT Tool Installation Script", ""]
        
        print(f"{Fore.CYAN}Generating installation script...{Style.RESET_ALL}\n")
        
        for category, tools in self.tools_config.items():
            script_lines.append(f"# {category.replace('_', ' ').title()} Tools")
            
            for tool_name, tool_config in tools.items():
                result = self.check_tool_availability(tool_name, tool_config)
                
                if not result['available']:
                    install_hint = tool_config.get('install_hint', f'# Install {tool_name} manually')
                    script_lines.append(f"echo 'Installing {tool_name}...'")
                    script_lines.append(install_hint)
                    script_lines.append("")
                    
            script_lines.append("")
            
        # Save script
        script_file = "install_vapt_tools.sh"
        
        try:
            with open(script_file, 'w') as f:
                f.write('\n'.join(script_lines))
            os.chmod(script_file, 0o755)
            
            print(f"Installation script saved to: {Fore.GREEN}{script_file}{Style.RESET_ALL}")
            print(f"Run with: {Fore.CYAN}chmod +x {script_file} && ./{script_file}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}Error saving installation script: {str(e)}{Style.RESET_ALL}")
            
    def check_tool_for_vapt_type(self, vapt_type):
        """Check tools specifically needed for a VAPT type"""
        vapt_tool_mapping = {
            'network': ['critical_tools', 'network_tools', 'ssl_tools', 'general_tools'],
            'web': ['critical_tools', 'web_tools', 'ssl_tools', 'general_tools'],
            'cloud': ['critical_tools', 'cloud_tools', 'general_tools'],
            'api': ['critical_tools', 'api_tools', 'web_tools', 'ssl_tools', 'general_tools']
        }
        
        required_categories = vapt_tool_mapping.get(vapt_type, ['critical_tools'])
        
        print(f"{Fore.CYAN}Checking tools for {vapt_type.upper()} VAPT...{Style.RESET_ALL}\n")
        
        all_available = True
        
        for category in required_categories:
            if category in self.tools_config:
                results = self.check_category_tools(category)
                
                # Check if any tools in this category are missing
                for tool_name, result in results.items():
                    if not result['available']:
                        all_available = False
                        
        return all_available
        
    def install_missing_tool(self, tool_name, tool_config):
        """Automatically install a missing tool"""
        install_hint = tool_config.get('install_hint', '')
        
        if not install_hint:
            return False, "No installation method available"
            
        print(f"  {Fore.YELLOW}Installing {tool_name}...{Style.RESET_ALL}")
        
        try:
            # Parse the installation command
            if install_hint.startswith('sudo apt-get install'):
                # Extract package name from apt-get command
                package = install_hint.replace('sudo apt-get install ', '').strip()
                cmd = ['apt-get', 'update', '&&', 'apt-get', 'install', '-y', package]
                
                # Run installation
                result = subprocess.run(
                    f"apt-get update && apt-get install -y {package}",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout for installation
                )
                
                if result.returncode == 0:
                    # Verify installation worked
                    time.sleep(2)  # Brief pause before verification
                    verification = self.check_tool_availability(tool_name, tool_config)
                    
                    if verification['available']:
                        print(f"    {Fore.GREEN}✓ Successfully installed {tool_name}{Style.RESET_ALL}")
                        return True, "Installation successful"
                    else:
                        print(f"    {Fore.RED}✗ Installation completed but tool not available{Style.RESET_ALL}")
                        return False, "Installation verification failed"
                else:
                    error_msg = result.stderr.strip() if result.stderr else "Unknown installation error"
                    print(f"    {Fore.RED}✗ Installation failed: {error_msg}{Style.RESET_ALL}")
                    return False, error_msg
                    
            elif install_hint.startswith('pip3 install'):
                # Extract package name from pip command
                package = install_hint.replace('pip3 install ', '').strip()
                
                result = subprocess.run(
                    ['pip3', 'install', package],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if result.returncode == 0:
                    time.sleep(2)
                    verification = self.check_tool_availability(tool_name, tool_config)
                    
                    if verification['available']:
                        print(f"    {Fore.GREEN}✓ Successfully installed {tool_name}{Style.RESET_ALL}")
                        return True, "Installation successful"
                    else:
                        print(f"    {Fore.RED}✗ Installation completed but tool not available{Style.RESET_ALL}")
                        return False, "Installation verification failed"
                else:
                    error_msg = result.stderr.strip() if result.stderr else "Unknown pip installation error"
                    print(f"    {Fore.RED}✗ Pip installation failed: {error_msg}{Style.RESET_ALL}")
                    return False, error_msg
                    
            elif 'git clone' in install_hint:
                print(f"    {Fore.YELLOW}⚠️  Git-based installation requires manual setup{Style.RESET_ALL}")
                print(f"    Command: {install_hint}")
                return False, "Manual git installation required"
                
            else:
                print(f"    {Fore.YELLOW}⚠️  Manual installation required{Style.RESET_ALL}")
                print(f"    Instructions: {install_hint}")
                return False, "Manual installation required"
                
        except subprocess.TimeoutExpired:
            print(f"    {Fore.RED}✗ Installation timeout (exceeded 5 minutes){Style.RESET_ALL}")
            return False, "Installation timeout"
        except Exception as e:
            print(f"    {Fore.RED}✗ Installation error: {str(e)}{Style.RESET_ALL}")
            return False, str(e)
    
    def auto_install_missing_tools(self, categories=None):
        """Automatically install missing tools from specified categories"""
        if categories is None:
            categories = list(self.tools_config.keys())
            
        print(f"{Fore.CYAN}🔧 AUTOMATIC TOOL INSTALLATION{Style.RESET_ALL}")
        print("="*50)
        print()
        
        installation_results = {
            'successful': [],
            'failed': [],
            'manual': [],
            'skipped': []
        }
        
        for category in categories:
            if category not in self.tools_config:
                continue
                
            print(f"{Fore.CYAN}Installing {category.replace('_', ' ').title()} Tools{Style.RESET_ALL}")
            print("-" * 40)
            
            tools = self.tools_config[category]
            
            for tool_name, tool_config in tools.items():
                # Check current availability
                result = self.check_tool_availability(tool_name, tool_config)
                
                if result['available']:
                    print(f"  ✓ {Fore.GREEN}{tool_name}{Style.RESET_ALL} - Already installed")
                    installation_results['skipped'].append(tool_name)
                else:
                    # Attempt installation
                    success, message = self.install_missing_tool(tool_name, tool_config)
                    
                    if success:
                        installation_results['successful'].append(tool_name)
                    elif 'manual' in message.lower():
                        installation_results['manual'].append(tool_name)
                    else:
                        installation_results['failed'].append((tool_name, message))
                        
            print()
            
        # Installation Summary
        print(f"{Fore.CYAN}INSTALLATION SUMMARY{Style.RESET_ALL}")
        print("="*30)
        print(f"✓ Successfully installed: {Fore.GREEN}{len(installation_results['successful'])}{Style.RESET_ALL}")
        print(f"✗ Failed installations: {Fore.RED}{len(installation_results['failed'])}{Style.RESET_ALL}")  
        print(f"⚠️  Manual installation required: {Fore.YELLOW}{len(installation_results['manual'])}{Style.RESET_ALL}")
        print(f"- Already installed: {len(installation_results['skipped'])}")
        print()
        
        if installation_results['successful']:
            print(f"{Fore.GREEN}Successfully Installed:{Style.RESET_ALL}")
            for tool in installation_results['successful']:
                print(f"  • {tool}")
            print()
            
        if installation_results['failed']:
            print(f"{Fore.RED}Failed Installations:{Style.RESET_ALL}")
            for tool, reason in installation_results['failed']:
                print(f"  • {tool}: {reason}")
            print()
            
        if installation_results['manual']:
            print(f"{Fore.YELLOW}Manual Installation Required:{Style.RESET_ALL}")
            for tool in installation_results['manual']:
                print(f"  • {tool}")
            print()
            
        return installation_results
        
    def check_all_dependencies_with_install_option(self):
        """Check all dependencies with option to auto-install missing tools"""
        print(f"{Fore.CYAN}VAPT TOOL DEPENDENCY CHECK{Style.RESET_ALL}")
        print("="*50)
        print()
        
        # Check critical tools first
        critical_ok = self.check_critical_tools()
        
        if not critical_ok:
            print(f"{Fore.RED}⚠️  Critical tools missing! Some functionality may not work.{Style.RESET_ALL}\n")
            
        # Check category-specific tools
        categories = ['network_tools', 'web_tools', 'ssl_tools', 'api_tools', 'cloud_tools', 'general_tools']
        missing_tools = []
        
        for category in categories:
            if category in self.tools_config:
                results = self.check_category_tools(category)
                for tool_name, result in results.items():
                    if not result['available']:
                        missing_tools.append((category, tool_name))
                
        # Summary
        print(f"{Fore.CYAN}DEPENDENCY CHECK SUMMARY{Style.RESET_ALL}")
        print("-"*30)
        
        total_tools = 0
        available_tools = 0
        
        for category, tools in self.tools_config.items():
            for tool_name, tool_config in tools.items():
                total_tools += 1
                result = self.check_tool_availability(tool_name, tool_config)
                if result['available']:
                    available_tools += 1
                    
        print(f"Available tools: {available_tools}/{total_tools}")
        coverage = (available_tools / total_tools) * 100 if total_tools > 0 else 0
        
        if coverage >= 90:
            print(f"Coverage: {Fore.GREEN}{coverage:.1f}%{Style.RESET_ALL} - Excellent")
        elif coverage >= 70:
            print(f"Coverage: {Fore.YELLOW}{coverage:.1f}%{Style.RESET_ALL} - Good")
        else:
            print(f"Coverage: {Fore.RED}{coverage:.1f}%{Style.RESET_ALL} - Poor")
            
        print()
        
        if missing_tools:
            print(f"{Fore.YELLOW}💡 {len(missing_tools)} tools are missing{Style.RESET_ALL}")
            print(f"\nOptions:")
            print(f"  1. {Fore.GREEN}Auto-install missing tools{Style.RESET_ALL}")
            print(f"  2. {Fore.CYAN}Generate installation script{Style.RESET_ALL}")
            print(f"  3. {Fore.YELLOW}Continue without installing{Style.RESET_ALL}")
            print()
            
            choice = input("Enter your choice (1-3): ").strip()
            
            if choice == "1":
                print()
                self.auto_install_missing_tools()
                print("\n" + "="*50)
                print("Re-checking dependencies after installation...")
                print("="*50)
                return self.check_all_dependencies()
            elif choice == "2":
                self.get_tool_installation_script()
            else:
                print(f"{Fore.YELLOW}Continuing with current tool availability{Style.RESET_ALL}")
                
        return critical_ok
        
    def get_alternative_tools(self, missing_tool):
        """Get alternative tools if primary tool is missing"""
        alternatives = {
            'nmap': ['masscan + nc', 'unicornscan'],
            'nikto': ['dirb + manual testing', 'gobuster + curl'],
            'sqlmap': ['manual SQL injection testing', 'burp suite'],
            'gobuster': ['dirb', 'ffuf', 'dirsearch'],
            'sslscan': ['testssl.sh', 'openssl s_client'],
            'masscan': ['nmap with timing options', 'zmap'],
            'enum4linux': ['smbclient + rpcclient', 'manual SMB enumeration']
        }
        
        return alternatives.get(missing_tool, ['Manual testing methods'])
        
    def validate_tool_functionality(self, tool_name, target="example.com"):
        """Validate that a tool works correctly with a basic test"""
        basic_tests = {
            'nmap': ['nmap', '-sn', target],
            'curl': ['curl', '-I', f'https://{target}'],
            'dig': ['dig', target],
            'whois': ['whois', target],
            'ping': ['ping', '-c', '1', target]
        }
        
        if tool_name not in basic_tests:
            return {'functional': True, 'note': 'No basic test available'}
            
        try:
            result = subprocess.run(
                basic_tests[tool_name],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            return {
                'functional': result.returncode == 0,
                'output': result.stdout[:200] + '...' if len(result.stdout) > 200 else result.stdout,
                'error': result.stderr if result.returncode != 0 else None
            }
            
        except Exception as e:
            return {
                'functional': False,
                'error': str(e)
            }
