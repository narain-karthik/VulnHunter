"""
Reporting Phase - Comprehensive report generation and remediation recommendations
Handles the creation of detailed security assessment reports with findings and recommendations
"""

import os
import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from colorama import Fore, Style
from utils.output_formatter import OutputFormatter
import html
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

class ReportingPhase:
    def __init__(self):
        self.output = OutputFormatter()
        
    def generate_report(self, vapt_module, target, session):
        """Generate interactive comprehensive report"""
        self.output.print_section_header("REPORTING AND REMEDIATION")
        
        report_data = self.compile_report_data(vapt_module, target, session)
        
        # Ask user for report preferences
        report_format = self.get_report_format()
        include_details = self.get_detail_level()
        
        # Generate reports in requested formats
        generated_reports = []
        
        if 'html' in report_format:
            html_report = self.generate_html_report(report_data, session, include_details)
            generated_reports.append(html_report)
            
        if 'json' in report_format:
            json_report = self.generate_json_report(report_data, session)
            generated_reports.append(json_report)
            
        if 'txt' in report_format:
            txt_report = self.generate_text_report(report_data, session, include_details)
            generated_reports.append(txt_report)
            
        if 'pdf' in report_format:
            pdf_report = self.generate_pdf_report(report_data, session, include_details)
            generated_reports.append(pdf_report)
            
        # Generate executive summary
        exec_summary = self.generate_executive_summary(report_data, session)
        generated_reports.append(exec_summary)
        
        # Generate remediation plan
        remediation_plan = self.generate_remediation_plan(report_data, session)
        generated_reports.append(remediation_plan)
        
        self.output.print_success("Reports generated successfully!")
        self.display_report_summary(generated_reports)
        
        return {
            'reports_generated': generated_reports,
            'report_data': report_data
        }
        
    def generate_automated_report(self, vapt_module, target, session):
        """Generate automated comprehensive report with all formats"""
        self.output.print_info("Generating automated comprehensive report...")
        
        report_data = self.compile_report_data(vapt_module, target, session)
        
        # Generate all report formats
        generated_reports = []
        
        # Generate PDF report as primary format
        pdf_report = self.generate_pdf_report(report_data, session, detailed=True)
        generated_reports.append(pdf_report)
        
        html_report = self.generate_html_report(report_data, session, detailed=True)
        generated_reports.append(html_report)
        
        txt_report = self.generate_text_report(report_data, session, detailed=True)
        generated_reports.append(txt_report)
        
        exec_summary = self.generate_executive_summary(report_data, session)
        generated_reports.append(exec_summary)
        
        remediation_plan = self.generate_remediation_plan(report_data, session)
        generated_reports.append(remediation_plan)
        
        self.output.print_success("Automated report generation completed!")
        
        return {
            'reports_generated': generated_reports,
            'report_data': report_data
        }
        
    def compile_report_data(self, vapt_module, target, session):
        """Compile all assessment data into a structured report format with detailed penetration testing findings"""
        report_data = {
            'metadata': {
                'assessment_type': vapt_module.vapt_type,
                'target': target,
                'session_id': session['id'],
                'start_time': session['start_time'],
                'end_time': datetime.now(),
                'duration': self.calculate_duration(session['start_time']),
                'assessor': 'VulnHunter Automated Security Assessment Platform',
                'report_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            },
            'executive_summary': {},
            'methodology': {},
            'findings': {
                'vulnerabilities': [],
                'risks': {},
                'exploits': [],
                'penetration_testing': {}
            },
            'recommendations': [],
            'penetration_testing_summary': {}
        }
        
        # Extract detailed penetration testing findings
        if 'penetration_testing' in session:
            pt_data = session['penetration_testing']
            report_data['findings']['penetration_testing'] = {
                'exploits_attempted': pt_data.get('exploits_attempted', []),
                'successful_exploits': pt_data.get('successful_exploits', []),
                'post_exploitation': pt_data.get('post_exploitation', {}),
                'credentials_discovered': pt_data.get('post_exploitation', {}).get('credentials_found', []),
                'sensitive_data_found': pt_data.get('post_exploitation', {}).get('sensitive_data', []),
                'system_information': pt_data.get('post_exploitation', {}).get('system_information', []),
                'evidence_collected': pt_data.get('post_exploitation', {}).get('evidence_collected', [])
            }
            
            # Create penetration testing summary
            report_data['penetration_testing_summary'] = {
                'total_exploits_attempted': len(pt_data.get('exploits_attempted', [])),
                'successful_exploitations': len(pt_data.get('successful_exploits', [])),
                'credentials_compromised': len(pt_data.get('post_exploitation', {}).get('credentials_found', [])),
                'data_exposures': len(pt_data.get('post_exploitation', {}).get('sensitive_data', [])),
                'system_access_level': self.assess_system_access_level(pt_data.get('post_exploitation', {}))
            }
        
        # Compile vulnerability findings from all phases
        vulnerabilities = []
        
        # From vulnerability assessment
        if 'vulnerability_assessment' in session:
            vuln_data = session['vulnerability_assessment']
            for finding in vuln_data.get('findings', []):
                vulnerabilities.append({
                    'type': finding.get('type', 'Unknown Vulnerability'),
                    'severity': finding.get('severity', 'Medium'),
                    'description': finding.get('description', 'No description'),
                    'category': finding.get('category', 'General'),
                    'tool_output': finding.get('tool_output', ''),
                    'cvss_score': finding.get('cvss_score', 'Not Assessed'),
                    'detection_method': 'Vulnerability Assessment'
                })
        
        # From penetration testing
        if 'penetration_testing' in session:
            pt_data = session['penetration_testing']
            for exploit in pt_data.get('successful_exploits', []):
                vulnerabilities.append({
                    'type': f"Exploitable: {exploit.get('name', 'Unknown Exploit')}",
                    'severity': 'High',
                    'description': f"Successfully exploited vulnerability using {exploit.get('name', 'unknown exploit')}",
                    'category': 'Penetration Testing',
                    'tool_output': exploit.get('output', ''),
                    'cvss_score': exploit.get('cvss_score', 'High'),
                    'detection_method': 'Penetration Testing'
                })
        
        report_data['findings']['vulnerabilities'] = vulnerabilities
        
        # Calculate risk levels
        report_data['findings']['risks'] = self.calculate_risk_levels(vulnerabilities)
        
        # Generate recommendations
        report_data['recommendations'] = self.generate_recommendations(vulnerabilities)
        
        # Create executive summary
        report_data['executive_summary'] = self.create_executive_summary(report_data)
        
        # Add methodology information
        report_data['methodology'] = {
            'methodology': f'{vapt_module.vapt_type.upper()} Security Assessment',
            'tools_used': self.get_tools_used(session),
            'scope': {
                'target': target,
                'inclusions': [f'{vapt_module.vapt_type} security testing'],
                'exclusions': ['Production data modification', 'Service disruption']
            }
        }
        
        return report_data
    
    def assess_system_access_level(self, post_exploitation_data):
        """Assess the level of system access achieved during penetration testing"""
        credentials = post_exploitation_data.get('credentials_found', [])
        sensitive_data = post_exploitation_data.get('sensitive_data', [])
        system_info = post_exploitation_data.get('system_information', [])
        
        if credentials:
            # Check for admin/root credentials
            for cred in credentials:
                if any(admin_term in cred.get('username', '').lower() for admin_term in ['admin', 'root', 'administrator']):
                    return 'Administrative'
                if cred.get('privilege', '').lower() in ['admin', 'administrator', 'root']:
                    return 'Administrative'
            
            # Regular user credentials
            return 'User Level'
        
        if sensitive_data or system_info:
            return 'Information Access'
            
        return 'Limited Access'
    
    def get_tools_used(self, session):
        """Extract list of tools used during assessment"""
        tools = ['VulnHunter Security Framework']
        
        # Add phase-specific tools
        if 'reconnaissance' in session:
            tools.extend(['Network Discovery', 'Port Scanning', 'Service Enumeration'])
        
        if 'vulnerability_assessment' in session:
            tools.extend(['Vulnerability Scanner', 'Security Analysis'])
            
        if 'penetration_testing' in session:
            tools.extend(['Metasploit Framework', 'Exploit-DB Database', 'Manual Exploitation'])
            
        return tools
        
        # Extract planning information
        if 'planning' in session:
            planning = session['planning']
            report_data['methodology'] = {
                'objectives': planning.get('objectives', []),
                'scope': planning.get('scope', {}),
                'methodology': planning.get('methodology', 'Standard'),
                'tools_used': planning.get('tools', [])
            }
            
        # Extract reconnaissance data
        if 'reconnaissance' in session:
            recon = session['reconnaissance']
            report_data['technical_details']['reconnaissance'] = {
                'passive_recon': recon.get('passive_recon', {}),
                'active_recon': recon.get('active_recon', {}),
                'assets_discovered': self.extract_discovered_assets(recon)
            }
            
        # Extract vulnerability assessment data
        if 'vulnerability_assessment' in session:
            va = session['vulnerability_assessment']
            report_data['findings']['vulnerabilities'] = va.get('vulnerabilities', [])
            report_data['findings']['risks'] = self.calculate_risk_levels(va.get('vulnerabilities', []))
            report_data['technical_details']['vulnerability_assessment'] = va.get('scan_results', {})
            
        # Extract penetration testing data
        if 'penetration_testing' in session:
            pt = session['penetration_testing']
            report_data['findings']['exploits'] = pt.get('successful_exploits', [])
            report_data['technical_details']['penetration_testing'] = {
                'exploits_attempted': pt.get('exploits_attempted', []),
                'successful_exploits': pt.get('successful_exploits', []),
                'post_exploitation': pt.get('post_exploitation', {})
            }
            
        # Generate recommendations
        report_data['recommendations'] = self.generate_recommendations(report_data['findings'])
        
        # Generate executive summary
        report_data['executive_summary'] = self.create_executive_summary(report_data)
        
        return report_data
        
    def get_report_format(self):
        """Get user preference for report format"""
        print(f"{Fore.YELLOW}Select report format(s):{Style.RESET_ALL}")
        print("1. Professional PDF Report (recommended)")
        print("2. HTML Report")
        print("3. Text Report (simple)")
        print("4. JSON Report (technical/machine-readable)")
        print("5. All formats")
        
        choice = input(f"{Fore.CYAN}Enter choice (1-5): {Style.RESET_ALL}").strip()
        
        format_map = {
            '1': ['pdf'],
            '2': ['html'],
            '3': ['txt'],
            '4': ['json'],
            '5': ['pdf', 'html', 'txt', 'json']
        }
        
        return format_map.get(choice, ['pdf'])
        
    def get_detail_level(self):
        """Get user preference for detail level"""
        print(f"\n{Fore.YELLOW}Select detail level:{Style.RESET_ALL}")
        print("1. Executive Summary only")
        print("2. Standard detail")
        print("3. Full technical detail")
        
        choice = input(f"{Fore.CYAN}Enter choice (1-3): {Style.RESET_ALL}").strip()
        
        return choice == '3'
        
    def generate_html_report(self, report_data, session, detailed=False):
        """Generate HTML report using template"""
        try:
            # Load HTML template
            template_path = os.path.join(os.path.dirname(__file__), '..', 'templates')
            env = Environment(loader=FileSystemLoader(template_path))
            template = env.get_template('report_template.html')
            
            # Render template with data
            html_content = template.render(
                report_data=report_data,
                detailed=detailed,
                session=session
            )
            
            # Save HTML report
            report_file = os.path.join(session['directory'], 'vapt_report.html')
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            return {
                'format': 'HTML',
                'filename': 'vapt_report.html',
                'path': report_file,
                'size': len(html_content)
            }
            
        except Exception as e:
            self.output.print_error(f"Error generating HTML report: {str(e)}")
            return {'format': 'HTML', 'error': str(e)}
            
    def generate_json_report(self, report_data, session):
        """Generate JSON report"""
        try:
            # Save JSON report
            report_file = os.path.join(session['directory'], 'vapt_report.json')
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
                
            return {
                'format': 'JSON',
                'filename': 'vapt_report.json',
                'path': report_file,
                'size': os.path.getsize(report_file)
            }
            
        except Exception as e:
            self.output.print_error(f"Error generating JSON report: {str(e)}")
            return {'format': 'JSON', 'error': str(e)}
            
    def generate_text_report(self, report_data, session, detailed=False):
        """Generate plain text report"""
        try:
            report_content = []
            
            # Header
            report_content.append("="*80)
            report_content.append("VULNERABILITY ASSESSMENT AND PENETRATION TESTING REPORT")
            report_content.append("="*80)
            report_content.append("")
            
            # Metadata
            metadata = report_data['metadata']
            report_content.append("ASSESSMENT DETAILS")
            report_content.append("-"*20)
            report_content.append(f"Assessment Type: {metadata['assessment_type'].upper()}")
            report_content.append(f"Target: {metadata['target']}")
            report_content.append(f"Date: {metadata['report_date']}")
            report_content.append(f"Duration: {metadata['duration']}")
            report_content.append("")
            
            # Executive Summary
            exec_summary = report_data['executive_summary']
            report_content.append("EXECUTIVE SUMMARY")
            report_content.append("-"*17)
            report_content.append(f"Risk Level: {exec_summary.get('overall_risk', 'Unknown')}")
            report_content.append(f"Total Vulnerabilities: {exec_summary.get('total_vulnerabilities', 0)}")
            report_content.append(f"Critical Issues: {exec_summary.get('critical_issues', 0)}")
            report_content.append("")
            
            # Findings
            vulnerabilities = report_data['findings']['vulnerabilities']
            if vulnerabilities:
                report_content.append("VULNERABILITY FINDINGS")
                report_content.append("-"*21)
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    report_content.append(f"{i}. {vuln.get('type', 'Unknown Vulnerability')}")
                    report_content.append(f"   Severity: {vuln.get('severity', 'Unknown')}")
                    report_content.append(f"   Description: {vuln.get('description', 'No description')}")
                    if detailed and 'tool_output' in vuln:
                        report_content.append(f"   Technical Details: {vuln['tool_output'][:200]}...")
                    report_content.append("")
                    
            # Recommendations
            recommendations = report_data['recommendations']
            if recommendations:
                report_content.append("RECOMMENDATIONS")
                report_content.append("-"*15)
                
                for i, rec in enumerate(recommendations, 1):
                    report_content.append(f"{i}. {rec.get('title', 'Recommendation')}")
                    report_content.append(f"   Priority: {rec.get('priority', 'Medium')}")
                    report_content.append(f"   Description: {rec.get('description', 'No description')}")
                    report_content.append("")
                    
            # Save text report
            report_file = os.path.join(session['directory'], 'vapt_report.txt')
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(report_content))
                
            return {
                'format': 'TXT',
                'filename': 'vapt_report.txt',
                'path': report_file,
                'size': len('\n'.join(report_content))
            }
            
        except Exception as e:
            self.output.print_error(f"Error generating text report: {str(e)}")
            return {'format': 'TXT', 'error': str(e)}
            
    def generate_executive_summary(self, report_data, session):
        """Generate executive summary document"""
        try:
            summary_content = []
            
            # Header
            summary_content.append("EXECUTIVE SUMMARY")
            summary_content.append("VAPT ASSESSMENT")
            summary_content.append("="*50)
            summary_content.append("")
            
            exec_summary = report_data['executive_summary']
            
            # Key findings
            summary_content.append("KEY FINDINGS:")
            summary_content.append(f"• Overall Risk Level: {exec_summary.get('overall_risk', 'Unknown')}")
            summary_content.append(f"• Total Vulnerabilities: {exec_summary.get('total_vulnerabilities', 0)}")
            summary_content.append(f"• Critical Issues: {exec_summary.get('critical_issues', 0)}")
            summary_content.append(f"• High Risk Issues: {exec_summary.get('high_risk_issues', 0)}")
            summary_content.append("")
            
            # Business impact
            summary_content.append("BUSINESS IMPACT:")
            summary_content.append(exec_summary.get('business_impact', 'Assessment of business impact pending detailed analysis.'))
            summary_content.append("")
            
            # Immediate actions
            summary_content.append("IMMEDIATE ACTIONS REQUIRED:")
            immediate_actions = exec_summary.get('immediate_actions', [])
            if immediate_actions:
                for action in immediate_actions:
                    summary_content.append(f"• {action}")
            else:
                summary_content.append("• Review detailed findings and implement recommended security controls")
            summary_content.append("")
            
            # Save executive summary
            summary_file = os.path.join(session['directory'], 'executive_summary.txt')
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(summary_content))
                
            return {
                'format': 'Executive Summary',
                'filename': 'executive_summary.txt',
                'path': summary_file,
                'size': len('\n'.join(summary_content))
            }
            
        except Exception as e:
            self.output.print_error(f"Error generating executive summary: {str(e)}")
            return {'format': 'Executive Summary', 'error': str(e)}
            
    def generate_remediation_plan(self, report_data, session):
        """Generate detailed remediation plan"""
        try:
            remediation_content = []
            
            # Header
            remediation_content.append("REMEDIATION PLAN")
            remediation_content.append("="*50)
            remediation_content.append("")
            
            recommendations = report_data['recommendations']
            
            # Sort by priority
            priority_order = {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4}
            sorted_recommendations = sorted(
                recommendations, 
                key=lambda x: priority_order.get(x.get('priority', 'Medium'), 3)
            )
            
            current_priority = None
            for i, rec in enumerate(sorted_recommendations, 1):
                priority = rec.get('priority', 'Medium')
                
                if priority != current_priority:
                    if current_priority is not None:
                        remediation_content.append("")
                    remediation_content.append(f"{priority.upper()} PRIORITY ITEMS:")
                    remediation_content.append("-" * (len(priority) + 15))
                    current_priority = priority
                    
                remediation_content.append(f"{i}. {rec.get('title', 'Remediation Item')}")
                remediation_content.append(f"   Issue: {rec.get('issue', 'Security vulnerability')}")
                remediation_content.append(f"   Solution: {rec.get('description', 'Apply security controls')}")
                remediation_content.append(f"   Effort: {rec.get('effort', 'Medium')}")
                remediation_content.append(f"   Timeline: {rec.get('timeline', '1-2 weeks')}")
                remediation_content.append("")
                
            # Save remediation plan
            remediation_file = os.path.join(session['directory'], 'remediation_plan.txt')
            with open(remediation_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(remediation_content))
                
            return {
                'format': 'Remediation Plan',
                'filename': 'remediation_plan.txt',
                'path': remediation_file,
                'size': len('\n'.join(remediation_content))
            }
            
        except Exception as e:
            self.output.print_error(f"Error generating remediation plan: {str(e)}")
            return {'format': 'Remediation Plan', 'error': str(e)}
            
    def calculate_duration(self, start_time):
        """Calculate assessment duration"""
        try:
            if isinstance(start_time, str):
                start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            else:
                start = start_time
                
            duration = datetime.now() - start
            hours = duration.total_seconds() / 3600
            
            if hours < 1:
                return f"{int(duration.total_seconds() / 60)} minutes"
            else:
                return f"{hours:.1f} hours"
                
        except:
            return "Unknown"
            
    def extract_discovered_assets(self, recon_data):
        """Extract discovered assets from reconnaissance data"""
        assets = []
        
        # Extract from passive reconnaissance
        passive = recon_data.get('passive_recon', {})
        if 'subdomain_enum' in passive:
            assets.extend(passive['subdomain_enum'])
            
        # Extract from active reconnaissance
        active = recon_data.get('active_recon', {})
        if 'port_scan' in active and 'open_ports' in active['port_scan']:
            for port in active['port_scan']['open_ports']:
                assets.append(f"Port {port.get('port', 'unknown')} - {port.get('service', 'unknown')}")
                
        return assets
        
    def calculate_risk_levels(self, vulnerabilities):
        """Calculate risk levels from vulnerabilities"""
        risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Medium')
            if severity in risk_counts:
                risk_counts[severity] += 1
                
        return risk_counts
        
    def generate_recommendations(self, vulnerabilities):
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []
        
        # Handle both cases: when vulnerabilities is passed directly or as part of findings
        if isinstance(vulnerabilities, dict) and 'vulnerabilities' in vulnerabilities:
            vulnerabilities = vulnerabilities['vulnerabilities']
        elif not isinstance(vulnerabilities, list):
            vulnerabilities = []
        
        # Group vulnerabilities by type for recommendations
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            severity = vuln.get('severity', 'Medium')
            
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(severity)
            
        # Generate recommendations for each vulnerability type
        for vuln_type, severities in vuln_types.items():
            highest_severity = self.get_highest_severity(severities)
            recommendation = self.get_recommendation_for_vulnerability(vuln_type, highest_severity)
            if recommendation:
                recommendations.append(recommendation)
                
        # Add general security recommendations
        general_recommendations = self.get_general_recommendations()
        recommendations.extend(general_recommendations)
        
        return recommendations
        
    def get_highest_severity(self, severities):
        """Get the highest severity from a list"""
        severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        
        highest = 'Low'
        highest_score = 1
        
        for severity in severities:
            score = severity_order.get(severity, 1)
            if score > highest_score:
                highest_score = score
                highest = severity
                
        return highest
        
    def get_recommendation_for_vulnerability(self, vuln_type, severity):
        """Get specific recommendation for vulnerability type"""
        recommendations_map = {
            'SQL Injection': {
                'title': 'Fix SQL Injection Vulnerabilities',
                'priority': severity,
                'issue': 'SQL injection vulnerabilities allow attackers to manipulate database queries',
                'description': 'Implement parameterized queries, input validation, and least privilege database access',
                'effort': 'Medium',
                'timeline': '1-2 weeks'
            },
            'Cross-Site Scripting': {
                'title': 'Implement XSS Protection',
                'priority': severity,
                'issue': 'XSS vulnerabilities allow code injection in web applications',
                'description': 'Implement input validation, output encoding, and Content Security Policy',
                'effort': 'Medium',
                'timeline': '1-2 weeks'
            },
            'Missing Security Header': {
                'title': 'Implement Security Headers',
                'priority': 'Medium',
                'issue': 'Missing security headers reduce defense against common attacks',
                'description': 'Configure security headers: X-Frame-Options, CSP, HSTS, X-Content-Type-Options',
                'effort': 'Low',
                'timeline': '1 week'
            },
            'SSL/TLS Issue': {
                'title': 'Fix SSL/TLS Configuration',
                'priority': severity,
                'issue': 'SSL/TLS misconfigurations can expose data in transit',
                'description': 'Update SSL/TLS configuration, disable weak ciphers, implement HSTS',
                'effort': 'Medium',
                'timeline': '1 week'
            },
            'Information Disclosure': {
                'title': 'Reduce Information Disclosure',
                'priority': 'Low',
                'issue': 'System information disclosure assists attackers in reconnaissance',
                'description': 'Remove or customize server banners, error messages, and version information',
                'effort': 'Low',
                'timeline': '1 week'
            }
        }
        
        return recommendations_map.get(vuln_type)
        
    def get_general_recommendations(self):
        """Get general security recommendations"""
        return [
            {
                'title': 'Implement Security Monitoring',
                'priority': 'High',
                'issue': 'Lack of security monitoring reduces incident response capability',
                'description': 'Deploy SIEM solution, configure log monitoring, and establish incident response procedures',
                'effort': 'High',
                'timeline': '4-6 weeks'
            },
            {
                'title': 'Regular Security Assessments',
                'priority': 'Medium',
                'issue': 'Infrequent security assessments allow vulnerabilities to persist',
                'description': 'Establish regular vulnerability scanning and penetration testing schedule',
                'effort': 'Medium',
                'timeline': 'Ongoing'
            },
            {
                'title': 'Security Awareness Training',
                'priority': 'Medium',
                'issue': 'Human factor remains a significant security risk',
                'description': 'Implement regular security awareness training for all personnel',
                'effort': 'Medium',
                'timeline': 'Quarterly'
            }
        ]
        
    def create_executive_summary(self, report_data):
        """Create enhanced executive summary with penetration testing findings"""
        vulnerabilities = report_data['findings']['vulnerabilities']
        
        # Calculate summary statistics
        total_vulns = len(vulnerabilities)
        risk_levels = report_data['findings']['risks']
        critical_issues = risk_levels.get('Critical', 0)
        high_risk_issues = risk_levels.get('High', 0)
        medium_risk_issues = risk_levels.get('Medium', 0)
        low_risk_issues = risk_levels.get('Low', 0)
        
        # Include penetration testing summary
        pt_summary = report_data.get('penetration_testing_summary', {})
        
        # Determine overall risk (enhanced with penetration testing results)
        if critical_issues > 0 or pt_summary.get('system_access_level') == 'Administrative':
            overall_risk = 'Critical'
        elif high_risk_issues > 0 or pt_summary.get('credentials_compromised', 0) > 0:
            overall_risk = 'High'
        elif medium_risk_issues > 0 or pt_summary.get('successful_exploitations', 0) > 0:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'
            
        # Enhanced business impact assessment
        business_impact = self.assess_business_impact(overall_risk, pt_summary)
            
        # Enhanced immediate actions based on penetration testing findings
        immediate_actions = []
        if critical_issues > 0:
            immediate_actions.append("Address critical vulnerabilities immediately")
        if pt_summary.get('credentials_compromised', 0) > 0:
            immediate_actions.append("Reset all compromised credentials and review access controls")
        if pt_summary.get('system_access_level') == 'Administrative':
            immediate_actions.append("Implement immediate administrative access controls and monitoring")
        if pt_summary.get('data_exposures', 0) > 0:
            immediate_actions.append("Assess and secure exposed sensitive data")
        if high_risk_issues > 0:
            immediate_actions.append("Plan remediation for high-risk issues within 1 week")
        immediate_actions.append("Review and implement security recommendations")
        
        return {
            'overall_risk': overall_risk,
            'total_vulnerabilities': total_vulns,
            'critical_issues': critical_issues,
            'high_risk_issues': high_risk_issues,
            'medium_risk_issues': medium_risk_issues,
            'low_risk_issues': low_risk_issues,
            'business_impact': business_impact,
            'immediate_actions': immediate_actions,
            'penetration_testing_impact': pt_summary
        }
    
    def assess_business_impact(self, overall_risk, pt_summary):
        """Assess business impact including penetration testing results"""
        base_impact = ""
        
        if overall_risk == 'Critical':
            base_impact = "CRITICAL: Immediate attention required. "
        elif overall_risk == 'High':
            base_impact = "HIGH: Urgent remediation needed. "
        elif overall_risk == 'Medium':
            base_impact = "MEDIUM: Planned remediation recommended. "
        else:
            base_impact = "LOW: Continue regular security maintenance. "
        
        # Add penetration testing specific impact
        if pt_summary.get('system_access_level') == 'Administrative':
            base_impact += "Administrative system access was achieved, indicating severe security control failure. "
        elif pt_summary.get('credentials_compromised', 0) > 0:
            base_impact += f"{pt_summary['credentials_compromised']} user credentials were compromised. "
        
        if pt_summary.get('data_exposures', 0) > 0:
            base_impact += f"Sensitive data exposure confirmed with {pt_summary['data_exposures']} categories of data at risk. "
        
        if pt_summary.get('successful_exploitations', 0) > 2:
            base_impact += "Multiple successful attack vectors demonstrate systemic security weaknesses. "
        
        return base_impact
        
    def generate_pdf_report(self, report_data, session, detailed=True):
        """Generate comprehensive professional PDF report with detailed penetration testing findings"""
        if not PDF_AVAILABLE:
            self.output.print_warning("PDF generation not available. Install reportlab package.")
            return self.generate_text_report(report_data, session, detailed)
            
        try:
            report_file = os.path.join(session['directory'], f"vapt_security_report_{session['id']}.pdf")
            
            # Create PDF document
            doc = SimpleDocTemplate(report_file, pagesize=A4,
                                    rightMargin=72, leftMargin=72,
                                    topMargin=72, bottomMargin=18)
            
            # Get styles
            styles = getSampleStyleSheet()
            story = []
            
            # Create custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=TA_CENTER,
                textColor=colors.darkblue
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                spaceBefore=20,
                spaceAfter=12,
                textColor=colors.darkblue
            )
            
            subheading_style = ParagraphStyle(
                'CustomSubHeading',
                parent=styles['Heading3'],
                fontSize=14,
                spaceBefore=15,
                spaceAfter=8,
                textColor=colors.darkred
            )
            
            critical_style = ParagraphStyle(
                'CriticalStyle',
                parent=styles['Normal'],
                fontSize=12,
                spaceBefore=10,
                spaceAfter=10,
                textColor=colors.red,
                backColor=colors.mistyrose
            )
            
            # Title Page
            story.append(Paragraph("VULNERABILITY ASSESSMENT<br/>& PENETRATION TESTING REPORT", title_style))
            story.append(Spacer(1, 30))
            
            # VulnHunter branding
            story.append(Paragraph("Generated by VulnHunter - Advanced Security Testing Platform", styles['Normal']))
            story.append(Spacer(1, 50))
            
            # Metadata table
            metadata = report_data['metadata']
            meta_data = [
                ['Assessment Type:', metadata['assessment_type'].upper()],
                ['Target System:', metadata['target']],
                ['Assessment Date:', metadata['report_date']],
                ['Test Duration:', metadata['duration']],
                ['Session ID:', metadata['session_id']],
                ['Testing Framework:', 'VulnHunter with Metasploit & Exploit-DB Integration'],
                ['Report Classification:', 'CONFIDENTIAL - SECURITY ASSESSMENT']
            ]
            
            meta_table = Table(meta_data, colWidths=[2.5*inch, 4*inch])
            meta_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (1, 0), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(meta_table)
            story.append(PageBreak())
            
            # Executive Summary
            exec_summary = report_data['executive_summary']
            story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
            
            if exec_summary:
                # Risk level with color coding
                risk_level = exec_summary.get('overall_risk', 'Not Assessed')
                if risk_level.lower() == 'critical':
                    risk_color = colors.red
                elif risk_level.lower() == 'high':
                    risk_color = colors.orange
                elif risk_level.lower() == 'medium':
                    risk_color = colors.yellow
                else:
                    risk_color = colors.green
                    
                story.append(Paragraph(f"<font color='{risk_color}'>Overall Security Risk: {risk_level.upper()}</font>", styles['Heading3']))
                story.append(Spacer(1, 15))
                
                summary_data = [
                    ['Total Vulnerabilities Identified:', str(exec_summary.get('total_vulnerabilities', 0))],
                    ['Critical Security Issues:', str(exec_summary.get('critical_issues', 0))],
                    ['High Risk Issues:', str(exec_summary.get('high_risk_issues', 0))],
                    ['Medium Risk Issues:', str(exec_summary.get('medium_risk_issues', 0))],
                    ['Low Risk Issues:', str(exec_summary.get('low_risk_issues', 0))]
                ]
                
                summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 11),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(summary_table)
                story.append(Spacer(1, 20))
                
                # Business Impact
                story.append(Paragraph("Business Impact Assessment", subheading_style))
                business_impact = exec_summary.get('business_impact', 'Assessment pending detailed analysis.')
                story.append(Paragraph(business_impact, styles['Normal']))
                story.append(Spacer(1, 15))
                
                # Immediate Actions
                immediate_actions = exec_summary.get('immediate_actions', [])
                if immediate_actions:
                    story.append(Paragraph("Immediate Actions Required", subheading_style))
                    for action in immediate_actions:
                        story.append(Paragraph(f"• {action}", styles['Normal']))
                    story.append(Spacer(1, 20))
                    
            story.append(PageBreak())
            
            # Add Penetration Testing Findings Section
            if 'penetration_testing' in session and session['penetration_testing']:
                story.append(Paragraph("PENETRATION TESTING FINDINGS", heading_style))
                pt_data = session['penetration_testing']
                
                # Exploit Summary
                story.append(Paragraph("Exploitation Summary", subheading_style))
                exploits_attempted = len(pt_data.get('exploits_attempted', []))
                successful_exploits = len(pt_data.get('successful_exploits', []))
                
                exploit_summary_data = [
                    ['Total Exploits Attempted:', str(exploits_attempted)],
                    ['Successful Exploitations:', str(successful_exploits)],
                    ['Success Rate:', f"{(successful_exploits/exploits_attempted*100):.1f}%" if exploits_attempted > 0 else "0%"]
                ]
                
                exploit_table = Table(exploit_summary_data, colWidths=[3*inch, 2*inch])
                exploit_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 11),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(exploit_table)
                story.append(Spacer(1, 20))
                
                # Discovered Credentials Section
                post_exploit = pt_data.get('post_exploitation', {})
                if post_exploit.get('credentials_found'):
                    story.append(Paragraph("🔑 DISCOVERED CREDENTIALS", critical_style))
                    story.append(Spacer(1, 10))
                    
                    cred_data = [['Username', 'Password', 'Source', 'Privilege Level']]
                    for cred in post_exploit['credentials_found']:
                        cred_data.append([
                            cred.get('username', 'N/A'),
                            cred.get('password', 'N/A'),
                            cred.get('source', 'N/A'),
                            cred.get('privilege', 'N/A')
                        ])
                    
                    cred_table = Table(cred_data, colWidths=[1.3*inch, 1.3*inch, 1.5*inch, 1.5*inch])
                    cred_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.mistyrose),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    
                    story.append(cred_table)
                    story.append(Spacer(1, 20))
                
                # Sensitive Data Discovery Section
                if post_exploit.get('sensitive_data'):
                    story.append(Paragraph("📊 SENSITIVE DATA DISCOVERED", subheading_style))
                    story.append(Spacer(1, 10))
                    
                    for data in post_exploit['sensitive_data']:
                        data_text = f"<b>{data.get('type', 'Unknown')}:</b> {data.get('description', 'No description')}"
                        if 'count' in data:
                            data_text += f" (Count: {data['count']})"
                        if 'data' in data:
                            data_text += f"<br/>Sample: <font color='blue'>{data['data']}</font>"
                        story.append(Paragraph(data_text, styles['Normal']))
                        story.append(Spacer(1, 8))
                    
                    story.append(Spacer(1, 15))
                
                # System Information Access
                if post_exploit.get('system_information'):
                    story.append(Paragraph("🖥️ SYSTEM INFORMATION ACCESS", subheading_style))
                    story.append(Spacer(1, 10))
                    
                    sys_data = [['File/Resource', 'Information Discovered']]
                    for info in post_exploit['system_information']:
                        sys_data.append([
                            info.get('file', 'N/A'),
                            info.get('info', 'N/A')
                        ])
                    
                    sys_table = Table(sys_data, colWidths=[2*inch, 4*inch])
                    sys_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.lightcyan),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    
                    story.append(sys_table)
                    story.append(Spacer(1, 20))
                
                # Evidence Collection
                if post_exploit.get('evidence_collected'):
                    story.append(Paragraph("🔍 EVIDENCE COLLECTED", subheading_style))
                    story.append(Spacer(1, 10))
                    
                    for evidence in post_exploit['evidence_collected']:
                        story.append(Paragraph(f"• {evidence}", styles['Normal']))
                    story.append(Spacer(1, 20))
                
                # Risk Assessment
                story.append(Paragraph("⚠️ RISK ASSESSMENT", critical_style))
                story.append(Spacer(1, 10))
                
                if post_exploit.get('credentials_found'):
                    story.append(Paragraph("🔴 HIGH RISK: Administrative credentials compromised", 
                                         ParagraphStyle('HighRisk', parent=styles['Normal'], 
                                                      textColor=colors.red, fontName='Helvetica-Bold')))
                if post_exploit.get('sensitive_data'):
                    story.append(Paragraph("🟡 MEDIUM RISK: Sensitive data exposure confirmed", 
                                         ParagraphStyle('MedRisk', parent=styles['Normal'], 
                                                      textColor=colors.orange, fontName='Helvetica-Bold')))
                if successful_exploits > 2:
                    story.append(Paragraph("🟠 MEDIUM RISK: Multiple attack vectors successful", 
                                         ParagraphStyle('MultRisk', parent=styles['Normal'], 
                                                      textColor=colors.orange, fontName='Helvetica-Bold')))
                
                story.append(Paragraph("📈 Impact: System compromise and data breach potential confirmed", 
                                     ParagraphStyle('Impact', parent=styles['Normal'], 
                                                  textColor=colors.darkred, fontName='Helvetica-Bold')))
                
                story.append(PageBreak())
            
            # Vulnerability Findings Section
            vulnerabilities = report_data['findings']['vulnerabilities']
            if vulnerabilities:
                story.append(Paragraph("VULNERABILITY FINDINGS", heading_style))
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    vuln_title = f"{i}. {vuln.get('type', 'Unknown Vulnerability')}"
                    story.append(Paragraph(vuln_title, subheading_style))
                    
                    vuln_details = [
                        ['Severity:', vuln.get('severity', 'Unknown')],
                        ['CVSS Score:', vuln.get('cvss_score', 'Not Assessed')],
                        ['Category:', vuln.get('category', 'General')],
                        ['Discovery Method:', vuln.get('detection_method', 'Automated Scan')]
                    ]
                    
                    vuln_table = Table(vuln_details, colWidths=[2*inch, 3*inch])
                    vuln_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    
                    story.append(vuln_table)
                    story.append(Spacer(1, 10))
                    
                    # Description
                    description = vuln.get('description', 'No description available.')
                    story.append(Paragraph(f"<b>Description:</b> {description}", styles['Normal']))
                    story.append(Spacer(1, 8))
                    
                    # Technical details if available
                    if detailed and vuln.get('tool_output'):
                        story.append(Paragraph("<b>Technical Details:</b>", styles['Normal']))
                        tech_details = vuln['tool_output'][:500] + "..." if len(vuln['tool_output']) > 500 else vuln['tool_output']
                        story.append(Paragraph(f"<font name='Courier' size='9'>{html.escape(tech_details)}</font>", styles['Normal']))
                        story.append(Spacer(1, 10))
                    
                    story.append(Spacer(1, 15))
                
                story.append(PageBreak())
            
            # Recommendations Section
            recommendations = report_data['recommendations']
            if recommendations:
                story.append(Paragraph("SECURITY RECOMMENDATIONS", heading_style))
                
                # Group by priority
                priority_groups = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
                for rec in recommendations:
                    priority = rec.get('priority', 'Medium')
                    if priority in priority_groups:
                        priority_groups[priority].append(rec)
                
                for priority in ['Critical', 'High', 'Medium', 'Low']:
                    if priority_groups[priority]:
                        priority_color = colors.red if priority == 'Critical' else colors.orange if priority == 'High' else colors.yellow if priority == 'Medium' else colors.green
                        story.append(Paragraph(f"{priority} Priority Recommendations", 
                                             ParagraphStyle('PriorityHeader', parent=subheading_style, 
                                                          textColor=priority_color)))
                        
                        for i, rec in enumerate(priority_groups[priority], 1):
                            story.append(Paragraph(f"{i}. {rec.get('title', 'Recommendation')}", styles['Heading4']))
                            story.append(Paragraph(f"<b>Issue:</b> {rec.get('issue', 'Security vulnerability')}", styles['Normal']))
                            story.append(Paragraph(f"<b>Solution:</b> {rec.get('description', 'Apply security controls')}", styles['Normal']))
                            story.append(Paragraph(f"<b>Implementation Effort:</b> {rec.get('effort', 'Medium')}", styles['Normal']))
                            story.append(Paragraph(f"<b>Timeline:</b> {rec.get('timeline', '1-2 weeks')}", styles['Normal']))
                            story.append(Spacer(1, 15))
                        
                        story.append(Spacer(1, 10))
                
                story.append(PageBreak())
            
            # Technical Methodology Section
            if report_data.get('methodology'):
                story.append(Paragraph("TESTING METHODOLOGY", heading_style))
                methodology = report_data['methodology']
                
                story.append(Paragraph(f"<b>Framework:</b> {methodology.get('methodology', 'OWASP Testing Guide')}", styles['Normal']))
                story.append(Spacer(1, 10))
                
                if methodology.get('tools_used'):
                    story.append(Paragraph("<b>Tools and Techniques Used:</b>", styles['Normal']))
                    for tool in methodology['tools_used']:
                        story.append(Paragraph(f"• {tool}", styles['Normal']))
                    story.append(Spacer(1, 15))
                
                if methodology.get('scope'):
                    scope = methodology['scope']
                    story.append(Paragraph("<b>Assessment Scope:</b>", styles['Normal']))
                    story.append(Paragraph(f"Target: {scope.get('target', 'Not specified')}", styles['Normal']))
                    
                    if scope.get('inclusions'):
                        story.append(Paragraph("Inclusions:", styles['Normal']))
                        for inclusion in scope['inclusions']:
                            story.append(Paragraph(f"• {inclusion}", styles['Normal']))
                    
                    if scope.get('exclusions'):
                        story.append(Paragraph("Exclusions:", styles['Normal']))
                        for exclusion in scope['exclusions']:
                            story.append(Paragraph(f"• {exclusion}", styles['Normal']))
                
                story.append(PageBreak())
            
            # Appendix - Technical Details
            if detailed:
                story.append(Paragraph("APPENDIX - TECHNICAL DETAILS", heading_style))
                
                # Include session information
                story.append(Paragraph("Assessment Session Information", subheading_style))
                session_info = [
                    ['Session ID:', session.get('id', 'Unknown')],
                    ['Start Time:', session.get('start_time', 'Unknown')],
                    ['Target:', session.get('target', 'Unknown')],
                    ['Assessment Type:', session.get('vapt_type', 'Unknown')],
                    ['Tool Versions:', 'VulnHunter v1.0 with Metasploit Framework & Exploit-DB Integration']
                ]
                
                session_table = Table(session_info, colWidths=[2*inch, 4*inch])
                session_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(session_table)
                story.append(Spacer(1, 20))
                
                # Disclaimer
                story.append(Paragraph("DISCLAIMER", subheading_style))
                disclaimer_text = """This security assessment was performed using automated vulnerability scanning and penetration testing tools. 
                The findings represent potential security vulnerabilities identified at the time of testing. Security posture may change over time, 
                and this report should be used as part of a comprehensive security program. The testing was conducted in a controlled manner 
                to minimize impact on production systems."""
                story.append(Paragraph(disclaimer_text, styles['Normal']))
            
            # Build PDF
            doc.build(story)
            
            # Get file size
            file_size = os.path.getsize(report_file)
            
            return {
                'format': 'Professional PDF Report',
                'filename': f"vapt_security_report_{session['id']}.pdf",
                'path': report_file,
                'size': file_size
            }
            
        except Exception as e:
            self.output.print_error(f"Error generating PDF report: {str(e)}")
            return {'format': 'PDF Report', 'error': str(e)}
    
    def create_readable_report_content(self, report_data, detailed=True):
        """Create formatted content for PDF report"""
        content = []
        
        # Header
        content.append("=" * 80)
        content.append("VULNERABILITY ASSESSMENT AND PENETRATION TESTING REPORT")
        content.append("=" * 80)
        content.append("")
        
        # Metadata
        metadata = report_data['metadata']
        content.append("ASSESSMENT INFORMATION")
        content.append("-" * 40)
        content.append(f"Assessment Type: {metadata['assessment_type'].upper()}")
        content.append(f"Target: {metadata['target']}")
        content.append(f"Assessment Date: {metadata['report_date']}")
        content.append(f"Session ID: {metadata['session_id']}")
        content.append(f"Duration: {metadata['duration']}")
        content.append("")
        
        # Executive Summary
        exec_summary = self.create_executive_summary(report_data)
        content.append("EXECUTIVE SUMMARY")
        content.append("-" * 40)
        content.append(f"Overall Risk Level: {exec_summary['overall_risk']}")
        content.append(f"Total Vulnerabilities Found: {exec_summary['total_vulnerabilities']}")
        content.append(f"Critical Issues: {exec_summary['critical_issues']}")
        content.append(f"High Risk Issues: {exec_summary['high_risk_issues']}")
        content.append("")
        content.append("Business Impact:")
        content.append(exec_summary['business_impact'])
        content.append("")
        content.append("Immediate Actions Required:")
        for action in exec_summary['immediate_actions']:
            content.append(f"• {action}")
        content.append("")
        
        # Vulnerabilities Found
        vulnerabilities = report_data['findings']['vulnerabilities']
        if vulnerabilities:
            content.append("VULNERABILITIES IDENTIFIED")
            content.append("-" * 40)
            for i, vuln in enumerate(vulnerabilities, 1):
                content.append(f"{i}. {vuln.get('title', 'Unknown Vulnerability')}")
                content.append(f"   Severity: {vuln.get('severity', 'Medium')}")
                content.append(f"   Type: {vuln.get('type', 'Unknown')}")
                content.append(f"   Description: {vuln.get('description', 'No description available')}")
                if vuln.get('location'):
                    content.append(f"   Location: {vuln.get('location')}")
                content.append("")
        else:
            content.append("VULNERABILITIES IDENTIFIED")
            content.append("-" * 40)
            content.append("No vulnerabilities were identified during this assessment.")
            content.append("")
        
        # Penetration Testing Results
        exploits = report_data['findings']['exploits']
        if exploits:
            content.append("PENETRATION TESTING RESULTS")
            content.append("-" * 40)
            for i, exploit in enumerate(exploits, 1):
                content.append(f"{i}. {exploit.get('name', 'Unknown Exploit')}")
                content.append(f"   Status: {exploit.get('status', 'Unknown')}")
                content.append(f"   Impact: {exploit.get('impact', 'Not specified')}")
                content.append("")
        
        # Recommendations
        recommendations = self.generate_recommendations(report_data['findings']['vulnerabilities'])
        if recommendations:
            content.append("REMEDIATION RECOMMENDATIONS")
            content.append("-" * 40)
            for i, rec in enumerate(recommendations, 1):
                content.append(f"{i}. {rec['title']}")
                content.append(f"   Priority: {rec['priority']}")
                content.append(f"   Timeline: {rec['timeline']}")
                content.append(f"   Description: {rec['description']}")
                content.append("")
        
        # Technical Details (if detailed report)
        if detailed and 'technical_details' in report_data:
            content.append("TECHNICAL DETAILS")
            content.append("-" * 40)
            
            # Reconnaissance data
            if 'reconnaissance' in report_data['technical_details']:
                recon = report_data['technical_details']['reconnaissance']
                content.append("Reconnaissance Phase:")
                if 'assets_discovered' in recon:
                    content.append(f"• Assets Discovered: {len(recon['assets_discovered'])}")
                content.append("")
        
        # Footer
        content.append("=" * 80)
        content.append("END OF REPORT")
        content.append("Generated by VAPT Automated Security Testing Tool")
        content.append("=" * 80)
        
        return "\n".join(content)

    def display_report_summary(self, generated_reports):
        """Display summary of generated reports"""
        self.output.print_info("Generated Reports:")
        
        for report in generated_reports:
            if 'error' not in report:
                print(f"  ✓ {report['format']}: {report['filename']} ({report['size']} bytes)")
            else:
                print(f"  ✗ {report['format']}: Error - {report['error']}")
