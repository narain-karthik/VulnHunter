"""
Output Formatter - Consistent terminal output formatting
Provides standardized formatting methods for colored terminal output
"""

import os
from datetime import datetime
from colorama import Fore, Style, init
from tabulate import tabulate

# Initialize colorama
init()

class OutputFormatter:
    def __init__(self):
        self.verbose = False
        self.log_file = None
        
    def set_verbose(self, verbose):
        """Enable or disable verbose output"""
        self.verbose = verbose
        
    def set_log_file(self, log_file):
        """Set log file for output logging"""
        self.log_file = log_file
        
    def print_banner(self, text, char="=", color=Fore.CYAN):
        """Print a banner with the specified text"""
        banner_width = min(80, max(len(text) + 4, 50))
        banner = char * banner_width
        
        print(f"{color}{banner}{Style.RESET_ALL}")
        print(f"{color}{text.center(banner_width)}{Style.RESET_ALL}")
        print(f"{color}{banner}{Style.RESET_ALL}")
        
    def print_section_header(self, text, color=Fore.CYAN):
        """Print a section header"""
        print(f"\n{color}{'=' * 60}{Style.RESET_ALL}")
        print(f"{color}{text.upper().center(60)}{Style.RESET_ALL}")
        print(f"{color}{'=' * 60}{Style.RESET_ALL}\n")
        
    def print_subsection_header(self, text, color=Fore.YELLOW):
        """Print a subsection header"""
        print(f"\n{color}{text}{Style.RESET_ALL}")
        print(f"{color}{'-' * len(text)}{Style.RESET_ALL}")
        
    def print_success(self, message):
        """Print a success message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] ✓ {message}"
        print(f"{Fore.GREEN}{formatted_message}{Style.RESET_ALL}")
        self._log_to_file(f"SUCCESS: {formatted_message}")
        
    def print_error(self, message):
        """Print an error message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] ✗ {message}"
        print(f"{Fore.RED}{formatted_message}{Style.RESET_ALL}")
        self._log_to_file(f"ERROR: {formatted_message}")
        
    def print_warning(self, message):
        """Print a warning message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] ⚠ {message}"
        print(f"{Fore.YELLOW}{formatted_message}{Style.RESET_ALL}")
        self._log_to_file(f"WARNING: {formatted_message}")
        
    def print_info(self, message):
        """Print an info message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] ℹ {message}"
        print(f"{Fore.BLUE}{formatted_message}{Style.RESET_ALL}")
        self._log_to_file(f"INFO: {formatted_message}")
        
    def print_debug(self, message):
        """Print a debug message (only if verbose mode is enabled)"""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            formatted_message = f"[{timestamp}] 🐛 {message}"
            print(f"{Fore.MAGENTA}{formatted_message}{Style.RESET_ALL}")
            self._log_to_file(f"DEBUG: {formatted_message}")
            
    def print_status(self, message, status="RUNNING"):
        """Print a status message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        status_colors = {
            "RUNNING": Fore.BLUE,
            "COMPLETED": Fore.GREEN,
            "FAILED": Fore.RED,
            "PENDING": Fore.YELLOW,
            "SKIPPED": Fore.CYAN
        }
        
        color = status_colors.get(status, Fore.WHITE)
        formatted_message = f"[{timestamp}] [{status}] {message}"
        print(f"{color}{formatted_message}{Style.RESET_ALL}")
        self._log_to_file(f"STATUS: {formatted_message}")
        
    def print_progress(self, current, total, prefix="Progress", bar_length=40):
        """Print a progress bar"""
        percent = (current / total) * 100
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        progress_text = f'\r{prefix}: |{bar}| {percent:.1f}% ({current}/{total})'
        print(f"{Fore.CYAN}{progress_text}{Style.RESET_ALL}", end='', flush=True)
        
        if current == total:
            print()  # New line when complete
            
    def print_table(self, headers, rows, title=None, table_format="grid"):
        """Print a formatted table"""
        if title:
            self.print_subsection_header(title)
            
        if not rows:
            print(f"{Fore.YELLOW}No data to display{Style.RESET_ALL}")
            return
            
        try:
            table = tabulate(rows, headers=headers, tablefmt=table_format)
            print(f"{Fore.WHITE}{table}{Style.RESET_ALL}")
        except Exception as e:
            self.print_error(f"Error formatting table: {str(e)}")
            # Fallback to simple format
            print(f"{Fore.CYAN}{' | '.join(headers)}{Style.RESET_ALL}")
            print("-" * (len(' | '.join(headers))))
            for row in rows:
                print(f"{Fore.WHITE}{' | '.join(str(cell) for cell in row)}{Style.RESET_ALL}")
                
    def print_key_value_pairs(self, data, title=None, indent=0):
        """Print key-value pairs in a formatted way"""
        if title:
            self.print_subsection_header(title)
            
        indent_str = "  " * indent
        
        for key, value in data.items():
            if isinstance(value, dict):
                print(f"{indent_str}{Fore.CYAN}{key}:{Style.RESET_ALL}")
                self.print_key_value_pairs(value, indent=indent + 1)
            elif isinstance(value, list):
                print(f"{indent_str}{Fore.CYAN}{key}:{Style.RESET_ALL}")
                for item in value:
                    print(f"{indent_str}  • {Fore.WHITE}{item}{Style.RESET_ALL}")
            else:
                print(f"{indent_str}{Fore.CYAN}{key}:{Style.RESET_ALL} {Fore.WHITE}{value}{Style.RESET_ALL}")
                
    def print_vulnerability_summary(self, vulnerabilities, title="Vulnerability Summary"):
        """Print a formatted vulnerability summary"""
        self.print_section_header(title)
        
        if not vulnerabilities:
            print(f"{Fore.GREEN}No vulnerabilities found!{Style.RESET_ALL}")
            return
            
        # Count vulnerabilities by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        # Define severity colors
        severity_colors = {
            'critical': Fore.MAGENTA,
            'high': Fore.RED,
            'medium': Fore.YELLOW,
            'low': Fore.BLUE,
            'informational': Fore.CYAN,
            'unknown': Fore.WHITE
        }
        
        # Print summary counts
        print(f"{Fore.CYAN}Total Vulnerabilities: {len(vulnerabilities)}{Style.RESET_ALL}\n")
        
        for severity in ['critical', 'high', 'medium', 'low', 'informational', 'unknown']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = severity_colors.get(severity, Fore.WHITE)
                print(f"{color}{severity.capitalize()}: {count}{Style.RESET_ALL}")
                
        # Print detailed vulnerability list
        print(f"\n{Fore.CYAN}Detailed Findings:{Style.RESET_ALL}")
        print("-" * 50)
        
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'Unknown').lower()
            color = severity_colors.get(severity, Fore.WHITE)
            
            print(f"\n{color}[{i}] {vuln.get('type', 'Unknown Vulnerability')}{Style.RESET_ALL}")
            print(f"    Severity: {color}{vuln.get('severity', 'Unknown')}{Style.RESET_ALL}")
            print(f"    Target: {Fore.WHITE}{vuln.get('location', vuln.get('target', 'Unknown'))}{Style.RESET_ALL}")
            
            description = vuln.get('description', 'No description available')
            if len(description) > 100:
                description = description[:100] + "..."
            print(f"    Description: {Fore.WHITE}{description}{Style.RESET_ALL}")
            
            if vuln.get('tool'):
                print(f"    Detected by: {Fore.CYAN}{vuln['tool']}{Style.RESET_ALL}")
                
    def print_tool_results(self, tool_name, results, show_output=False):
        """Print formatted tool execution results"""
        self.print_subsection_header(f"{tool_name} Results")
        
        status = results.get('status', 'unknown')
        status_colors = {
            'completed': Fore.GREEN,
            'error': Fore.RED,
            'timeout': Fore.YELLOW,
            'tool_not_found': Fore.RED,
            'running': Fore.BLUE
        }
        
        color = status_colors.get(status, Fore.WHITE)
        print(f"Status: {color}{status.upper()}{Style.RESET_ALL}")
        
        if 'start_time' in results:
            print(f"Start Time: {Fore.WHITE}{results['start_time']}{Style.RESET_ALL}")
            
        if 'end_time' in results:
            print(f"End Time: {Fore.WHITE}{results['end_time']}{Style.RESET_ALL}")
            
        if results.get('error'):
            print(f"Error: {Fore.RED}{results['error']}{Style.RESET_ALL}")
            
        if results.get('vulnerabilities_found'):
            vulns = results['vulnerabilities_found']
            print(f"Vulnerabilities Found: {Fore.YELLOW}{len(vulns)}{Style.RESET_ALL}")
            
            for vuln in vulns[:3]:  # Show first 3 vulnerabilities
                print(f"  • {Fore.WHITE}{vuln.get('description', 'No description')[:60]}...{Style.RESET_ALL}")
                
            if len(vulns) > 3:
                print(f"  ... and {len(vulns) - 3} more")
                
        if show_output and results.get('output'):
            print(f"\n{Fore.CYAN}Tool Output:{Style.RESET_ALL}")
            output = results['output']
            if len(output) > 1000:
                output = output[:1000] + f"\n... (truncated, {len(results['output']) - 1000} more characters)"
            print(f"{Fore.WHITE}{output}{Style.RESET_ALL}")
            
    def print_phase_completion(self, phase_name, duration=None, findings_count=None):
        """Print phase completion message"""
        message = f"Phase '{phase_name}' completed successfully"
        
        if duration:
            message += f" in {duration}"
            
        if findings_count is not None:
            message += f", {findings_count} findings"
            
        self.print_success(message)
        
    def print_assessment_summary(self, session_data):
        """Print a comprehensive assessment summary"""
        self.print_section_header("ASSESSMENT SUMMARY")
        
        # Basic information
        print(f"{Fore.CYAN}Target:{Style.RESET_ALL} {Fore.WHITE}{session_data.get('target', 'Unknown')}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Assessment Type:{Style.RESET_ALL} {Fore.WHITE}{session_data.get('type', 'Unknown').upper()}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Session ID:{Style.RESET_ALL} {Fore.WHITE}{session_data.get('id', 'Unknown')}{Style.RESET_ALL}")
        
        if 'start_time' in session_data:
            print(f"{Fore.CYAN}Start Time:{Style.RESET_ALL} {Fore.WHITE}{session_data['start_time']}{Style.RESET_ALL}")
            
        # Phases completed
        phases = session_data.get('phases_completed', [])
        if phases:
            print(f"\n{Fore.CYAN}Phases Completed:{Style.RESET_ALL}")
            for phase in phases:
                print(f"  ✓ {Fore.GREEN}{phase.replace('_', ' ').title()}{Style.RESET_ALL}")
                
        # Findings summary
        findings = session_data.get('findings', [])
        if findings:
            print(f"\n{Fore.CYAN}Total Findings:{Style.RESET_ALL} {Fore.WHITE}{len(findings)}{Style.RESET_ALL}")
            
        # Tools used
        tools = session_data.get('tools_used', [])
        if tools:
            print(f"\n{Fore.CYAN}Tools Used:{Style.RESET_ALL}")
            for tool in tools:
                print(f"  • {Fore.WHITE}{tool}{Style.RESET_ALL}")
                
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
    def print_separator(self, char="-", length=60, color=Fore.CYAN):
        """Print a separator line"""
        print(f"{color}{char * length}{Style.RESET_ALL}")
        
    def print_countdown(self, seconds, message="Starting in"):
        """Print a countdown timer"""
        import time
        
        for i in range(seconds, 0, -1):
            print(f"\r{Fore.YELLOW}{message} {i} seconds...{Style.RESET_ALL}", end='', flush=True)
            time.sleep(1)
        print(f"\r{Fore.GREEN}{message.replace('in', 'now!')}{Style.RESET_ALL}")
        
    def _log_to_file(self, message):
        """Log message to file if log file is set"""
        if self.log_file:
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    f.write(f"[{timestamp}] {message}\n")
            except Exception:
                pass  # Silently fail if logging fails
                
    def format_bytes(self, bytes_value):
        """Format bytes into human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} TB"
        
    def format_duration(self, seconds):
        """Format duration in seconds to human readable format"""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f} minutes"
        else:
            hours = seconds / 3600
            return f"{hours:.1f} hours"
            
    def print_json_formatted(self, data, title=None):
        """Print JSON data in a formatted way"""
        import json
        
        if title:
            self.print_subsection_header(title)
            
        try:
            formatted_json = json.dumps(data, indent=2, default=str)
            print(f"{Fore.WHITE}{formatted_json}{Style.RESET_ALL}")
        except Exception as e:
            self.print_error(f"Error formatting JSON: {str(e)}")
            print(f"{Fore.WHITE}{str(data)}{Style.RESET_ALL}")
