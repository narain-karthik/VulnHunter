#!/usr/bin/env python3
"""
VulnHunter - Main Entry Point
Comprehensive security testing workflows for Network, Web, Cloud, and API assessments
"""

import sys
import os
import argparse
from colorama import init, Fore, Style
from core.vapt_manager import VAPTManager
from utils.tool_checker import ToolChecker
from utils.output_formatter import OutputFormatter
from auth.authentication import require_authentication

# Initialize colorama for cross-platform colored output
init()

class VAPTCLITool:
    def __init__(self):
        self.vapt_manager = VAPTManager()
        self.tool_checker = ToolChecker()
        self.output = OutputFormatter()
        
    def display_banner(self):
        """Display application banner"""
        banner = f"""
{Fore.CYAN}
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║   ██║██║   ██║██║     ██╔██╗ ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}Automated Vulnerability Assessment and Penetration Testing Tool{Style.RESET_ALL}
{Fore.GREEN}Version 1.0 - Comprehensive Security Testing Framework{Style.RESET_ALL}
        """
        print(banner)
        
    def display_main_menu(self):
        """Display main VAPT type selection menu"""
        self.output.print_section_header("VAPT TYPE SELECTION")
        print(f"{Fore.CYAN}Select the type of VAPT assessment you want to perform:{Style.RESET_ALL}\n")
        
        options = [
            ("1", "Network VAPT", "Infrastructure and network security assessment"),
            ("2", "Web Application VAPT", "Web application security testing"),
            ("3", "Cloud VAPT", "Cloud infrastructure security assessment"),
            ("4", "API VAPT", "API security testing and validation"),
            ("5", "Tool Dependencies Check", "Verify required security tools"),
            ("6", "Auto-Install Missing Tools", "Automatically install missing security tools"),
            ("7", "Exit", "Exit the application")
        ]
        
        for option, title, description in options:
            print(f"{Fore.WHITE}[{option}]{Style.RESET_ALL} {Fore.GREEN}{title}{Style.RESET_ALL}")
            print(f"    {Fore.YELLOW}{description}{Style.RESET_ALL}\n")
            
    def handle_user_choice(self, choice):
        """Handle user menu selection"""
        try:
            if choice == "1":
                return self.vapt_manager.start_network_vapt()
            elif choice == "2":
                return self.vapt_manager.start_web_vapt()
            elif choice == "3":
                return self.vapt_manager.start_cloud_vapt()
            elif choice == "4":
                return self.vapt_manager.start_api_vapt()
            elif choice == "5":
                return self.tool_checker.check_all_dependencies()
            elif choice == "6":
                return self.tool_checker.check_all_dependencies_with_install_option()
            elif choice == "7":
                self.output.print_success("Thank you for using VulnHunter. Goodbye!")
                return False
            else:
                self.output.print_error("Invalid choice. Please select a valid option.")
                return True
        except KeyboardInterrupt:
            self.output.print_warning("\nOperation cancelled by user.")
            return True
        except Exception as e:
            self.output.print_error(f"An error occurred: {str(e)}")
            return True
            
    def run_interactive_mode(self):
        """Run the tool in interactive mode"""
        self.display_banner()
        
        # Check critical dependencies on startup
        if not self.tool_checker.check_critical_tools():
            self.output.print_error("Critical dependencies missing. Please install required tools.")
            return
            
        while True:
            try:
                self.display_main_menu()
                choice = input(f"{Fore.CYAN}Enter your choice (1-7): {Style.RESET_ALL}").strip()
                
                if not self.handle_user_choice(choice):
                    break
                    
                # Pause before showing menu again
                input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
                os.system('clear' if os.name == 'posix' else 'cls')
                
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Exiting VulnHunter...{Style.RESET_ALL}")
                break
            except EOFError:
                print(f"\n{Fore.YELLOW}Exiting VulnHunter...{Style.RESET_ALL}")
                break
                
    def run_automated_mode(self, vapt_type, target, config_file=None):
        """Run the tool in automated mode with predefined parameters"""
        self.display_banner()
        
        self.output.print_info(f"Starting automated {vapt_type} VAPT for target: {target}")
        
        if vapt_type.lower() == "network":
            return self.vapt_manager.start_network_vapt(target, automated=True, config_file=config_file)
        elif vapt_type.lower() == "web":
            return self.vapt_manager.start_web_vapt(target, automated=True, config_file=config_file)
        elif vapt_type.lower() == "cloud":
            return self.vapt_manager.start_cloud_vapt(target, automated=True, config_file=config_file)
        elif vapt_type.lower() == "api":
            return self.vapt_manager.start_api_vapt(target, automated=True, config_file=config_file)
        else:
            self.output.print_error(f"Unknown VAPT type: {vapt_type}")
            return False

def main():
    """Main function with authentication and argument parsing"""
    # SECURITY: Require authentication before accessing VulnHunter
    print(f"{Fore.MAGENTA}🔐 VulnHunter Security Authentication Required{Style.RESET_ALL}\n")
    
    if not require_authentication():
        print(f"{Fore.RED}❌ Authentication failed. Access denied to VulnHunter.{Style.RESET_ALL}")
        return False
    
    # Continue with normal application flow after successful authentication
    parser = argparse.ArgumentParser(
        description="VulnHunter - Comprehensive Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                    # Interactive mode
  python main.py --type network --target 192.168.1.0/24  # Automated network VAPT
  python main.py --type web --target https://example.com  # Automated web VAPT
  python main.py --check-tools                            # Check tool dependencies
        """
    )
    
    parser.add_argument(
        "--type", 
        choices=["network", "web", "cloud", "api"],
        help="Type of VAPT assessment to perform"
    )
    
    parser.add_argument(
        "--target",
        help="Target for the assessment (IP, domain, URL, etc.)"
    )
    
    parser.add_argument(
        "--config",
        help="Configuration file for automated assessment"
    )
    
    parser.add_argument(
        "--check-tools",
        action="store_true",
        help="Check availability of required security tools"
    )
    
    parser.add_argument(
        "--output-dir",
        default="./vapt_results",
        help="Directory to store assessment results (default: ./vapt_results)"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Initialize the tool
    vapt_tool = VAPTCLITool()
    
    # Set output directory
    os.makedirs(args.output_dir, exist_ok=True)
    vapt_tool.vapt_manager.set_output_directory(args.output_dir)
    
    # Enable verbose mode if requested
    if args.verbose:
        vapt_tool.output.set_verbose(True)
    
    # Handle tool checking
    if args.check_tools:
        vapt_tool.display_banner()
        return vapt_tool.tool_checker.check_all_dependencies()
    
    # Handle automated mode
    if args.type and args.target:
        return vapt_tool.run_automated_mode(args.type, args.target, args.config)
    
    # Handle partial arguments
    if args.type and not args.target:
        print(f"{Fore.RED}Error: --target is required when --type is specified{Style.RESET_ALL}")
        return False
        
    if args.target and not args.type:
        print(f"{Fore.RED}Error: --type is required when --target is specified{Style.RESET_ALL}")
        return False
    
    # Run interactive mode
    vapt_tool.run_interactive_mode()
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Program interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Fatal error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
