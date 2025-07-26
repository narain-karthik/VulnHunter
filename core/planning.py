"""
Planning Phase - Scope definition and methodology planning
Handles the initial planning and scoping phase of VAPT assessments
"""

import os
import json
from datetime import datetime
from colorama import Fore, Style
from utils.output_formatter import OutputFormatter

class PlanningPhase:
    def __init__(self):
        self.output = OutputFormatter()
        
    def execute_planning(self, vapt_module, target, session):
        """Execute interactive planning phase"""
        self.output.print_section_header("PLANNING AND SCOPE DEFINITION")
        
        # Get assessment objectives
        objectives = self.get_assessment_objectives(vapt_module.vapt_type)
        
        # Define scope
        scope = self.define_scope(vapt_module.vapt_type, target)
        
        # Select methodology
        methodology = self.select_methodology(vapt_module.vapt_type)
        
        # Choose tools
        tools = self.select_tools(vapt_module)
        
        # Define timeline
        timeline = self.define_timeline()
        
        # Create planning document
        planning_doc = {
            'assessment_type': vapt_module.vapt_type,
            'target': target,
            'objectives': objectives,
            'scope': scope,
            'methodology': methodology,
            'tools': tools,
            'timeline': timeline,
            'created_at': datetime.now().isoformat()
        }
        
        # Save planning document
        planning_file = os.path.join(session['directory'], 'planning.json')
        with open(planning_file, 'w') as f:
            json.dump(planning_doc, f, indent=2)
            
        session['planning'] = planning_doc
        self.output.print_success("Planning phase completed successfully!")
        
        return planning_doc
        
    def execute_automated_planning(self, vapt_module, target, session):
        """Execute automated planning with default configurations"""
        self.output.print_info("Executing automated planning phase...")
        
        planning_doc = {
            'assessment_type': vapt_module.vapt_type,
            'target': target,
            'objectives': vapt_module.get_default_objectives(),
            'scope': vapt_module.get_default_scope(target),
            'methodology': vapt_module.get_default_methodology(),
            'tools': vapt_module.get_default_tools(),
            'timeline': self.get_default_timeline(),
            'created_at': datetime.now().isoformat()
        }
        
        # Save planning document
        planning_file = os.path.join(session['directory'], 'planning.json')
        with open(planning_file, 'w') as f:
            json.dump(planning_doc, f, indent=2)
            
        session['planning'] = planning_doc
        self.output.print_success("Automated planning phase completed!")
        
        return planning_doc
        
    def get_assessment_objectives(self, vapt_type):
        """Get assessment objectives from user input"""
        self.output.print_info(f"Define objectives for {vapt_type} VAPT assessment:")
        
        default_objectives = self.get_default_objectives(vapt_type)
        
        print(f"\n{Fore.YELLOW}Default objectives for {vapt_type} VAPT:{Style.RESET_ALL}")
        for i, obj in enumerate(default_objectives, 1):
            print(f"{i}. {obj}")
            
        choice = input(f"\n{Fore.CYAN}Use default objectives? (y/n): {Style.RESET_ALL}").strip().lower()
        
        if choice in ['y', 'yes']:
            return default_objectives
        else:
            custom_objectives = []
            print(f"{Fore.YELLOW}Enter custom objectives (press Enter twice to finish):{Style.RESET_ALL}")
            while True:
                obj = input("Objective: ").strip()
                if not obj:
                    break
                custom_objectives.append(obj)
            return custom_objectives if custom_objectives else default_objectives
            
    def get_default_objectives(self, vapt_type):
        """Get default objectives based on VAPT type"""
        objectives_map = {
            'network': [
                "Identify network infrastructure and services",
                "Discover security vulnerabilities in network devices",
                "Assess network segmentation and access controls",
                "Test for network-based attacks and lateral movement",
                "Evaluate network monitoring and detection capabilities"
            ],
            'web': [
                "Identify web application vulnerabilities",
                "Test authentication and authorization mechanisms",
                "Assess input validation and data handling",
                "Evaluate session management and security controls",
                "Test for common web application attacks (OWASP Top 10)"
            ],
            'cloud': [
                "Assess cloud infrastructure configuration",
                "Evaluate cloud security controls and policies",
                "Test cloud service authentication and authorization",
                "Identify misconfigured cloud resources",
                "Assess data protection and privacy controls"
            ],
            'api': [
                "Test API authentication and authorization",
                "Assess API input validation and error handling",
                "Evaluate API rate limiting and abuse prevention",
                "Test for API-specific vulnerabilities",
                "Assess API documentation and security disclosure"
            ]
        }
        return objectives_map.get(vapt_type, ["General security assessment"])
        
    def define_scope(self, vapt_type, target):
        """Define assessment scope"""
        self.output.print_info("Define assessment scope:")
        
        scope = {
            'target': target,
            'inclusions': [],
            'exclusions': [],
            'constraints': []
        }
        
        # Get inclusions
        print(f"{Fore.YELLOW}What should be included in the scope?{Style.RESET_ALL}")
        print("1. All discovered assets")
        print("2. Specific IP ranges/URLs")
        print("3. Custom scope definition")
        
        choice = input(f"{Fore.CYAN}Choose scope type (1-3): {Style.RESET_ALL}").strip()
        
        if choice == "1":
            scope['inclusions'] = ["All discovered assets related to the target"]
        elif choice == "2":
            print("Enter IP ranges, URLs, or hostnames to include (one per line, empty line to finish):")
            while True:
                item = input("Include: ").strip()
                if not item:
                    break
                scope['inclusions'].append(item)
        else:
            print("Enter custom scope items (one per line, empty line to finish):")
            while True:
                item = input("Include: ").strip()
                if not item:
                    break
                scope['inclusions'].append(item)
        
        # Get exclusions
        print(f"\n{Fore.YELLOW}What should be excluded from the scope?{Style.RESET_ALL}")
        while True:
            item = input("Exclude (empty to finish): ").strip()
            if not item:
                break
            scope['exclusions'].append(item)
            
        return scope
        
    def select_methodology(self, vapt_type):
        """Select assessment methodology"""
        methodologies = {
            'network': [
                "NIST SP 800-115",
                "OWASP Testing Guide (Network)",
                "PTES (Penetration Testing Execution Standard)",
                "Custom methodology"
            ],
            'web': [
                "OWASP Testing Guide",
                "NIST SP 800-115",
                "WSTG (Web Security Testing Guide)",
                "Custom methodology"
            ],
            'cloud': [
                "CSA Cloud Security Alliance",
                "NIST Cloud Computing Security",
                "Cloud Security Alliance CCM",
                "Custom methodology"
            ],
            'api': [
                "OWASP API Security Top 10",
                "API Security Testing Guide",
                "Custom API testing methodology",
                "REST/GraphQL specific testing"
            ]
        }
        
        print(f"\n{Fore.YELLOW}Select testing methodology:{Style.RESET_ALL}")
        method_list = methodologies.get(vapt_type, ["Standard methodology"])
        
        for i, method in enumerate(method_list, 1):
            print(f"{i}. {method}")
            
        while True:
            try:
                choice = int(input(f"{Fore.CYAN}Select methodology (1-{len(method_list)}): {Style.RESET_ALL}"))
                if 1 <= choice <= len(method_list):
                    return method_list[choice - 1]
                else:
                    self.output.print_error(f"Please enter a number between 1 and {len(method_list)}")
            except ValueError:
                self.output.print_error("Please enter a valid number")
                
    def select_tools(self, vapt_module):
        """Select tools for the assessment"""
        print(f"\n{Fore.YELLOW}Select tools for {vapt_module.vapt_type} assessment:{Style.RESET_ALL}")
        
        available_tools = vapt_module.get_available_tools()
        selected_tools = []
        
        print("Available tools:")
        for i, (tool, description) in enumerate(available_tools.items(), 1):
            print(f"{i}. {tool} - {description}")
            
        choice = input(f"\n{Fore.CYAN}Select all tools? (y/n): {Style.RESET_ALL}").strip().lower()
        
        if choice in ['y', 'yes']:
            return list(available_tools.keys())
        else:
            print("Enter tool numbers to select (comma-separated):")
            try:
                selections = input("Tools: ").strip().split(',')
                tool_list = list(available_tools.keys())
                for sel in selections:
                    idx = int(sel.strip()) - 1
                    if 0 <= idx < len(tool_list):
                        selected_tools.append(tool_list[idx])
                return selected_tools
            except ValueError:
                self.output.print_warning("Invalid selection, using all tools")
                return list(available_tools.keys())
                
    def define_timeline(self):
        """Define assessment timeline"""
        print(f"\n{Fore.YELLOW}Define assessment timeline:{Style.RESET_ALL}")
        
        timeline = {}
        
        # Assessment duration
        try:
            duration = int(input("Assessment duration (hours): "))
            timeline['duration_hours'] = duration
        except ValueError:
            timeline['duration_hours'] = 8  # Default 8 hours
            
        # Break intervals
        try:
            break_interval = int(input("Break interval (minutes, 0 for no breaks): "))
            timeline['break_interval_minutes'] = break_interval
        except ValueError:
            timeline['break_interval_minutes'] = 60  # Default 1 hour
            
        timeline['start_time'] = datetime.now().isoformat()
        
        return timeline
        
    def get_default_timeline(self):
        """Get default timeline for automated assessments"""
        return {
            'duration_hours': 4,
            'break_interval_minutes': 0,
            'start_time': datetime.now().isoformat()
        }
