"""
VAPT Manager - Core orchestration module for VAPT workflows
Manages the overall flow and coordination between different VAPT phases
"""

import os
import time
from datetime import datetime
from colorama import Fore, Style
from core.planning import PlanningPhase
from core.reconnaissance import ReconnaissancePhase
from core.vulnerability_assessment import VulnerabilityAssessmentPhase
from core.penetration_testing import PenetrationTestingPhase
from core.reporting import ReportingPhase
from modules.network_vapt import NetworkVAPT
from modules.web_vapt import WebVAPT
from modules.cloud_vapt import CloudVAPT
from modules.api_vapt import APIVAPT
from utils.output_formatter import OutputFormatter
from utils.session_manager import SessionManager

class VAPTManager:
    def __init__(self):
        self.output = OutputFormatter()
        self.session_manager = SessionManager()
        self.output_directory = "./vapt_results"
        self.current_session = None
        
        # Initialize phase managers
        self.planning = PlanningPhase()
        self.reconnaissance = ReconnaissancePhase()
        self.vulnerability_assessment = VulnerabilityAssessmentPhase()
        self.penetration_testing = PenetrationTestingPhase()
        self.reporting = ReportingPhase()
        
        # Initialize VAPT modules
        self.network_vapt = NetworkVAPT()
        self.web_vapt = WebVAPT()
        self.cloud_vapt = CloudVAPT()
        self.api_vapt = APIVAPT()
        
    def get_vapt_module(self, vapt_type):
        """Get the appropriate VAPT module based on type"""
        modules = {
            'network': self.network_vapt,
            'web': self.web_vapt,
            'cloud': self.cloud_vapt,
            'api': self.api_vapt
        }
        return modules.get(vapt_type)
        
    def set_output_directory(self, directory):
        """Set the output directory for results"""
        self.output_directory = directory
        os.makedirs(directory, exist_ok=True)
        
    def create_session(self, vapt_type, target):
        """Create a new VAPT session"""
        session_id = f"{vapt_type}_{int(time.time())}"
        session_dir = os.path.join(self.output_directory, session_id)
        os.makedirs(session_dir, exist_ok=True)
        
        self.current_session = {
            'id': session_id,
            'type': vapt_type,
            'target': target,
            'start_time': datetime.now(),
            'directory': session_dir,
            'phases_completed': [],
            'findings': [],
            'tools_used': []
        }
        
        self.session_manager.save_session(self.current_session)
        return self.current_session
        
    def get_user_confirmation(self, phase_name, description):
        """Get user confirmation before proceeding to next phase"""
        self.output.print_section_header(f"PHASE CONFIRMATION: {phase_name}")
        print(f"{Fore.YELLOW}{description}{Style.RESET_ALL}\n")
        
        while True:
            choice = input(f"{Fore.CYAN}Do you want to proceed with this phase? (y/n/s/q): {Style.RESET_ALL}").strip().lower()
            
            if choice in ['y', 'yes']:
                return 'proceed'
            elif choice in ['n', 'no']:
                return 'skip'
            elif choice in ['s', 'skip']:
                return 'skip'
            elif choice in ['q', 'quit']:
                return 'quit'
            else:
                self.output.print_error("Please enter 'y' (yes), 'n' (no), 's' (skip), or 'q' (quit)")
                
    def execute_vapt_workflow(self, vapt_module, target, automated=False):
        """Execute the complete VAPT workflow"""
        try:
            self.output.print_success(f"Starting {vapt_module.vapt_type} VAPT for target: {target}")
            
            # Phase 1: Planning and Scope Definition
            if not automated:
                action = self.get_user_confirmation(
                    "Planning and Scope Definition",
                    "This phase will help you define the scope, objectives, and methodology for your assessment."
                )
                if action == 'quit':
                    return False
                elif action == 'proceed':
                    planning_result = self.planning.execute_planning(vapt_module, target, self.current_session)
                    if self.current_session:
                        self.current_session['phases_completed'].append('planning')
            else:
                planning_result = self.planning.execute_automated_planning(vapt_module, target, self.current_session)
                if self.current_session:
                    self.current_session['phases_completed'].append('planning')
            
            # Phase 2: Information Gathering and Reconnaissance
            if not automated:
                action = self.get_user_confirmation(
                    "Information Gathering and Reconnaissance",
                    "This phase includes passive and active reconnaissance to gather information about the target."
                )
                if action == 'quit':
                    return False
                elif action == 'proceed':
                    recon_result = self.reconnaissance.execute_reconnaissance(vapt_module, target, self.current_session)
                    if self.current_session:
                        self.current_session['phases_completed'].append('reconnaissance')
            else:
                recon_result = self.reconnaissance.execute_automated_reconnaissance(vapt_module, target, self.current_session)
                if self.current_session:
                    self.current_session['phases_completed'].append('reconnaissance')
            
            # Phase 3: Vulnerability Assessment
            if not automated:
                action = self.get_user_confirmation(
                    "Vulnerability Assessment",
                    "This phase will scan for and identify potential security vulnerabilities."
                )
                if action == 'quit':
                    return False
                elif action == 'proceed':
                    va_result = self.vulnerability_assessment.execute_assessment(vapt_module, target, self.current_session)
                    if self.current_session:
                        self.current_session['phases_completed'].append('vulnerability_assessment')
            else:
                va_result = self.vulnerability_assessment.execute_automated_assessment(vapt_module, target, self.current_session)
                if self.current_session:
                    self.current_session['phases_completed'].append('vulnerability_assessment')
            
            # Phase 4: Penetration Testing
            if not automated:
                action = self.get_user_confirmation(
                    "Penetration Testing",
                    "This phase will attempt to exploit identified vulnerabilities to assess their impact."
                )
                if action == 'quit':
                    return False
                elif action == 'proceed':
                    pt_result = self.penetration_testing.execute_testing(vapt_module, target, self.current_session)
                    if self.current_session:
                        self.current_session['phases_completed'].append('penetration_testing')
            else:
                pt_result = self.penetration_testing.execute_automated_testing(vapt_module, target, self.current_session)
                if self.current_session:
                    self.current_session['phases_completed'].append('penetration_testing')
            
            # Phase 5: Reporting and Remediation
            if not automated:
                action = self.get_user_confirmation(
                    "Reporting and Remediation",
                    "This phase will generate comprehensive reports and provide remediation recommendations."
                )
                if action == 'quit':
                    return False
                elif action == 'proceed':
                    report_result = self.reporting.generate_report(vapt_module, target, self.current_session)
                    if self.current_session:
                        self.current_session['phases_completed'].append('reporting')
            else:
                report_result = self.reporting.generate_automated_report(vapt_module, target, self.current_session)
                if self.current_session:
                    self.current_session['phases_completed'].append('reporting')
            
            # Mark session as completed
            if self.current_session:
                self.current_session['end_time'] = datetime.now()
                self.current_session['status'] = 'completed'
                self.session_manager.save_session(self.current_session)
            
            self.output.print_success("VAPT assessment completed successfully!")
            if self.current_session:
                self.output.print_info(f"Results saved to: {self.current_session['directory']}")
            
            return True
            
        except KeyboardInterrupt:
            self.output.print_warning("Assessment interrupted by user")
            if self.current_session:
                self.current_session['status'] = 'interrupted'
                self.session_manager.save_session(self.current_session)
            return False
        except Exception as e:
            self.output.print_error(f"Error during VAPT execution: {str(e)}")
            if self.current_session:
                self.current_session['status'] = 'error'
                self.session_manager.save_session(self.current_session)
            return False
    
    def start_network_vapt(self, target=None, automated=False, config_file=None):
        """Start Network VAPT assessment"""
        if not target and not automated:
            target = input(f"{Fore.CYAN}Enter target network (IP/CIDR): {Style.RESET_ALL}").strip()
            
        if not target:
            self.output.print_error("Target is required for network VAPT")
            return False
            
        self.create_session("network", target)
        return self.execute_vapt_workflow(self.network_vapt, target, automated)
    
    def start_web_vapt(self, target=None, automated=False, config_file=None):
        """Start Web Application VAPT assessment"""
        if not target and not automated:
            target = input(f"{Fore.CYAN}Enter target URL: {Style.RESET_ALL}").strip()
            
        if not target:
            self.output.print_error("Target URL is required for web application VAPT")
            return False
            
        self.create_session("web", target)
        return self.execute_vapt_workflow(self.web_vapt, target, automated)
    
    def start_cloud_vapt(self, target=None, automated=False, config_file=None):
        """Start Cloud VAPT assessment"""
        if not target and not automated:
            target = input(f"{Fore.CYAN}Enter cloud target (domain/service): {Style.RESET_ALL}").strip()
            
        if not target:
            self.output.print_error("Target is required for cloud VAPT")
            return False
            
        self.create_session("cloud", target)
        return self.execute_vapt_workflow(self.cloud_vapt, target, automated)
    
    def start_api_vapt(self, target=None, automated=False, config_file=None):
        """Start API VAPT assessment"""
        if not target and not automated:
            target = input(f"{Fore.CYAN}Enter API endpoint URL: {Style.RESET_ALL}").strip()
            
        if not target:
            self.output.print_error("API endpoint is required for API VAPT")
            return False
            
        self.create_session("api", target)
        return self.execute_vapt_workflow(self.api_vapt, target, automated)
