"""
Web Application VAPT Module - Web application security testing
Specialized module for web application vulnerability assessment and penetration testing
"""

from colorama import Fore, Style

class WebVAPT:
    def __init__(self):
        self.vapt_type = "web"
        
    def get_default_objectives(self):
        """Get default objectives for web application VAPT"""
        return [
            "Identify web application architecture and technologies",
            "Test authentication and authorization mechanisms",
            "Assess input validation and data handling",
            "Evaluate session management security",
            "Test for OWASP Top 10 vulnerabilities",
            "Assess client-side security controls",
            "Evaluate business logic flaws",
            "Test file upload and download functionality",
            "Assess API security (if applicable)",
            "Evaluate web application firewall effectiveness"
        ]
        
    def get_default_scope(self, target):
        """Get default scope for web application VAPT"""
        return {
            'target_application': target,
            'inclusions': [
                'All web application functionality',
                'User authentication systems',
                'Data input forms and interfaces',
                'File upload/download features',
                'API endpoints (if applicable)',
                'Administrative interfaces'
            ],
            'exclusions': [
                'Third-party integrations (unless explicitly authorized)',
                'Payment processing systems (without PCI authorization)',
                'Production database modifications',
                'Denial of service testing'
            ],
            'constraints': [
                'No data modification in production',
                'Limited automated scanning during business hours',
                'Respect application rate limiting',
                'No social engineering of users'
            ]
        }
        
    def get_default_methodology(self):
        """Get default methodology for web application VAPT"""
        return "OWASP Testing Guide v4.2"
        
    def get_default_tools(self):
        """Get default tools for web application VAPT"""
        return [
            'burp_suite', 'owasp_zap', 'nikto', 'dirb', 'gobuster',
            'sqlmap', 'xssstrike', 'wfuzz', 'ffuf', 'dirsearch'
        ]
        
    def get_available_tools(self):
        """Get available tools with descriptions"""
        return {
            'burp_suite': 'Comprehensive web application security testing platform',
            'owasp_zap': 'Open source web application security scanner',
            'nikto': 'Web server vulnerability scanner',
            'dirb': 'Web content discovery tool',
            'gobuster': 'Fast directory/file enumeration tool',
            'sqlmap': 'Automatic SQL injection testing tool',
            'xssstrike': 'Advanced XSS detection suite',
            'wfuzz': 'Web application fuzzer',
            'ffuf': 'Fast web fuzzer',
            'dirsearch': 'Advanced web path scanner',
            'whatweb': 'Web technology fingerprinting',
            'wafw00f': 'Web application firewall detection',
            'commix': 'Command injection exploitation tool',
            'csrf_tester': 'CSRF vulnerability testing tool'
        }
        
    def get_vulnerability_tools(self):
        """Get vulnerability assessment tools specific to web application testing"""
        return {
            'owasp_zap': 'Comprehensive web application vulnerability scanner',
            'nikto': 'Web server and application vulnerability scanner',
            'sqlmap': 'SQL injection vulnerability scanner',
            'xssstrike': 'Cross-site scripting vulnerability scanner',
            'nuclei': 'Fast web vulnerability scanner',
            'wpscan': 'WordPress vulnerability scanner',
            'joomscan': 'Joomla vulnerability scanner',
            'custom_checks': 'Custom web application vulnerability checks',
            'ssl_labs': 'SSL/TLS configuration assessment',
            'security_headers': 'HTTP security headers analysis'
        }
        
    def get_available_exploits(self):
        """Get available exploits for web application testing"""
        return [
            {
                'name': 'SQL Injection Test',
                'description': 'Test for SQL injection vulnerabilities',
                'type': 'sql_injection_test',
                'targets': ['database', 'input_fields'],
                'risk_level': 'high',
                'safe_for_automation': False
            },
            {
                'name': 'Cross-Site Scripting (XSS) Test',
                'description': 'Test for XSS vulnerabilities',
                'type': 'xss_test',
                'targets': ['input_fields', 'user_content'],
                'risk_level': 'medium',
                'safe_for_automation': True
            },
            {
                'name': 'Directory Traversal Test',
                'description': 'Test for directory traversal vulnerabilities',
                'type': 'directory_traversal_test',
                'targets': ['file_access', 'parameters'],
                'risk_level': 'medium',
                'safe_for_automation': True
            },
            {
                'name': 'File Upload Bypass',
                'description': 'Test file upload restrictions and validation',
                'type': 'file_upload_test',
                'targets': ['file_upload'],
                'risk_level': 'high',
                'safe_for_automation': False
            },
            {
                'name': 'Authentication Bypass',
                'description': 'Test for authentication bypass vulnerabilities',
                'type': 'auth_bypass_test',
                'targets': ['authentication'],
                'risk_level': 'high',
                'safe_for_automation': False
            },
            {
                'name': 'Session Management Test',
                'description': 'Test session management security',
                'type': 'session_test',
                'targets': ['session_management'],
                'risk_level': 'medium',
                'safe_for_automation': True
            },
            {
                'name': 'CSRF Token Test',
                'description': 'Test for CSRF protection mechanisms',
                'type': 'csrf_test',
                'targets': ['forms', 'state_changing_operations'],
                'risk_level': 'medium',
                'safe_for_automation': True
            },
            {
                'name': 'HTTP Security Headers Test',
                'description': 'Test for missing security headers',
                'type': 'security_headers_test',
                'targets': ['http_headers'],
                'risk_level': 'low',
                'safe_for_automation': True
            },
            {
                'name': 'Command Injection Test',
                'description': 'Test for command injection vulnerabilities',
                'type': 'command_injection_test',
                'targets': ['system_commands', 'input_fields'],
                'risk_level': 'critical',
                'safe_for_automation': False
            },
            {
                'name': 'XML External Entity (XXE) Test',
                'description': 'Test for XXE vulnerabilities',
                'type': 'xxe_test',
                'targets': ['xml_processing'],
                'risk_level': 'high',
                'safe_for_automation': False
            }
        ]
        
    def get_reconnaissance_methods(self):
        """Get reconnaissance methods specific to web application testing"""
        return {
            'passive': [
                'Web application fingerprinting',
                'Technology stack identification',
                'Search engine reconnaissance for application information',
                'SSL/TLS certificate analysis',
                'DNS and subdomain enumeration',
                'Social media and public information gathering',
                'Web archive analysis (Wayback Machine)',
                'Google dorking for application data'
            ],
            'active': [
                'Web application spidering and crawling',
                'Directory and file enumeration',
                'Technology fingerprinting',
                'Input field discovery and analysis',
                'Authentication mechanism identification',
                'Session management analysis',
                'Error message analysis',
                'Administrative interface discovery',
                'API endpoint enumeration',
                'Web application firewall detection'
            ]
        }
        
    def get_vulnerability_categories(self):
        """Get vulnerability categories for web application testing"""
        return [
            'Injection Vulnerabilities (SQL, NoSQL, Command, LDAP)',
            'Broken Authentication and Session Management',
            'Cross-Site Scripting (XSS)',
            'Insecure Direct Object References',
            'Security Misconfiguration',
            'Sensitive Data Exposure',
            'Missing Function Level Access Control',
            'Cross-Site Request Forgery (CSRF)',
            'Using Components with Known Vulnerabilities',
            'Unvalidated Redirects and Forwards',
            'Business Logic Flaws',
            'File Upload Vulnerabilities',
            'Information Disclosure',
            'HTTP Security Headers Issues'
        ]
        
    def get_testing_phases(self):
        """Get specific testing phases for web application VAPT"""
        return [
            {
                'phase': 'Information Gathering',
                'description': 'Identify application architecture and technologies',
                'tools': ['whatweb', 'wafw00f', 'burp_suite'],
                'duration': '1-2 hours'
            },
            {
                'phase': 'Application Mapping',
                'description': 'Map application functionality and attack surface',
                'tools': ['burp_suite', 'owasp_zap', 'gobuster'],
                'duration': '2-4 hours'
            },
            {
                'phase': 'Authentication Testing',
                'description': 'Test authentication and session management',
                'tools': ['burp_suite', 'custom_scripts'],
                'duration': '2-3 hours'
            },
            {
                'phase': 'Input Validation Testing',
                'description': 'Test all input vectors for vulnerabilities',
                'tools': ['sqlmap', 'xssstrike', 'burp_suite'],
                'duration': '4-6 hours'
            },
            {
                'phase': 'Authorization Testing',
                'description': 'Test access controls and privilege escalation',
                'tools': ['burp_suite', 'custom_scripts'],
                'duration': '2-4 hours'
            },
            {
                'phase': 'Business Logic Testing',
                'description': 'Test application-specific business logic',
                'tools': ['manual_testing', 'burp_suite'],
                'duration': '3-6 hours'
            }
        ]
        
    def get_owasp_top_10(self):
        """Get OWASP Top 10 vulnerabilities with testing approach"""
        return {
            'A01_Broken_Access_Control': {
                'description': 'Restrictions on authenticated users not properly enforced',
                'tests': ['Privilege escalation', 'Direct object reference', 'Missing authorization'],
                'tools': ['burp_suite', 'custom_scripts']
            },
            'A02_Cryptographic_Failures': {
                'description': 'Failures related to cryptography leading to sensitive data exposure',
                'tests': ['Weak encryption', 'Data in transit protection', 'Certificate validation'],
                'tools': ['sslscan', 'testssl', 'burp_suite']
            },
            'A03_Injection': {
                'description': 'Injection flaws occur when untrusted data is sent to an interpreter',
                'tests': ['SQL injection', 'NoSQL injection', 'Command injection', 'LDAP injection'],
                'tools': ['sqlmap', 'commix', 'burp_suite']
            },
            'A04_Insecure_Design': {
                'description': 'Risks related to design flaws and missing security controls',
                'tests': ['Threat modeling review', 'Security architecture analysis'],
                'tools': ['manual_analysis', 'design_review']
            },
            'A05_Security_Misconfiguration': {
                'description': 'Missing appropriate security hardening across application stack',
                'tests': ['Default configurations', 'Unnecessary features', 'Error handling'],
                'tools': ['nikto', 'burp_suite', 'custom_checks']
            },
            'A06_Vulnerable_Components': {
                'description': 'Using components with known vulnerabilities',
                'tests': ['Component identification', 'Version checking', 'CVE analysis'],
                'tools': ['retire.js', 'OWASP_dependency_check', 'nuclei']
            },
            'A07_Authentication_Failures': {
                'description': 'Application functions related to authentication and session management',
                'tests': ['Weak passwords', 'Session management', 'Credential recovery'],
                'tools': ['burp_suite', 'hydra', 'custom_scripts']
            },
            'A08_Software_Data_Integrity_Failures': {
                'description': 'Code and infrastructure that does not protect against integrity violations',
                'tests': ['Update mechanisms', 'CI/CD pipeline security', 'Unsigned data'],
                'tools': ['manual_analysis', 'burp_suite']
            },
            'A09_Security_Logging_Failures': {
                'description': 'Insufficient logging and monitoring',
                'tests': ['Log analysis', 'Monitoring coverage', 'Incident response'],
                'tools': ['log_analysis', 'manual_review']
            },
            'A10_Server_Side_Request_Forgery': {
                'description': 'SSRF flaws occur when web application fetches remote resources',
                'tests': ['URL validation', 'Internal resource access', 'Cloud metadata access'],
                'tools': ['burp_suite', 'ssrf_scanner', 'custom_payloads']
            }
        }
        
    def get_common_web_technologies(self):
        """Get common web technologies and their testing approaches"""
        return {
            'PHP': {
                'vulnerabilities': ['LFI/RFI', 'Code injection', 'Deserialization'],
                'tools': ['burp_suite', 'commix', 'php_filter_chain_generator']
            },
            'ASP.NET': {
                'vulnerabilities': ['ViewState manipulation', '.NET deserialization', 'Request validation bypass'],
                'tools': ['burp_suite', 'viewstate_decoder', 'ysoserial.net']
            },
            'Java': {
                'vulnerabilities': ['Deserialization', 'Expression language injection', 'XXE'],
                'tools': ['burp_suite', 'ysoserial', 'xxe_injector']
            },
            'Node.js': {
                'vulnerabilities': ['Prototype pollution', 'Command injection', 'Package vulnerabilities'],
                'tools': ['burp_suite', 'retire.js', 'npm_audit']
            },
            'Python': {
                'vulnerabilities': ['Template injection', 'Pickle deserialization', 'Import vulnerabilities'],
                'tools': ['burp_suite', 'tplmap', 'bandit']
            }
        }
        
    def get_authentication_testing_areas(self):
        """Get authentication testing areas and methods"""
        return {
            'Credential_Transport': [
                'HTTPS enforcement',
                'Credential transmission security',
                'Login form security'
            ],
            'Default_Credentials': [
                'Default usernames and passwords',
                'Administrative accounts',
                'Service accounts'
            ],
            'Weak_Password_Policy': [
                'Password complexity requirements',
                'Password length restrictions',
                'Password history and rotation'
            ],
            'Account_Lockout': [
                'Account lockout thresholds',
                'Lockout duration',
                'Unlock mechanisms'
            ],
            'Multi_Factor_Authentication': [
                'MFA implementation',
                'MFA bypass techniques',
                'Recovery mechanisms'
            ],
            'Session_Management': [
                'Session token generation',
                'Session timeout',
                'Session invalidation',
                'Concurrent sessions'
            ]
        }
        
    def get_input_validation_testing_vectors(self):
        """Get input validation testing vectors"""
        return {
            'SQL_Injection': [
                "' OR 1=1--",
                "'; DROP TABLE users--",
                "' UNION SELECT 1,2,3--",
                "1' AND (SELECT COUNT(*) FROM users) > 0--"
            ],
            'XSS': [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "';alert('XSS');//"
            ],
            'Directory_Traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ],
            'Command_Injection': [
                "; ls -la",
                "| whoami",
                "& ipconfig",
                "`id`"
            ],
            'LDAP_Injection': [
                "*)(uid=*))(|(uid=*",
                "admin)(&(password=*))",
                "*))(|(cn=*"
            ]
        }
        
    def get_business_logic_testing_areas(self):
        """Get business logic testing areas"""
        return [
            'Process flow bypass',
            'Parameter manipulation',
            'Race conditions',
            'Time and state vulnerabilities',
            'Workflow circumvention',
            'Payment logic flaws',
            'Privilege escalation through business logic',
            'Data validation bypass',
            'Negative testing scenarios',
            'Boundary value analysis'
        ]
        
    def get_risk_assessment_criteria(self):
        """Get risk assessment criteria for web application vulnerabilities"""
        return {
            'Critical': [
                'Remote code execution',
                'SQL injection with database access',
                'Authentication bypass',
                'Arbitrary file upload leading to code execution'
            ],
            'High': [
                'Privilege escalation vulnerabilities',
                'Stored XSS in administrative interfaces',
                'Direct object reference allowing data access',
                'Command injection vulnerabilities'
            ],
            'Medium': [
                'Reflected XSS vulnerabilities',
                'CSRF vulnerabilities',
                'Information disclosure',
                'Missing security headers'
            ],
            'Low': [
                'Verbose error messages',
                'Version disclosure',
                'Non-exploitable information leakage',
                'Minor configuration issues'
            ]
        }
        
    def validate_target(self, target):
        """Validate web application target URL"""
        import re
        
        # URL pattern validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        return bool(url_pattern.match(target))
        
    def get_remediation_guidelines(self):
        """Get remediation guidelines for web application security"""
        return {
            'Input_Validation': [
                'Implement server-side input validation',
                'Use parameterized queries for database access',
                'Encode output based on context',
                'Implement Content Security Policy (CSP)'
            ],
            'Authentication': [
                'Implement strong password policies',
                'Use multi-factor authentication',
                'Implement account lockout mechanisms',
                'Secure password recovery processes'
            ],
            'Session_Management': [
                'Use secure session tokens',
                'Implement proper session timeout',
                'Secure session storage and transmission',
                'Implement session invalidation'
            ],
            'Access_Control': [
                'Implement principle of least privilege',
                'Use role-based access control',
                'Validate access on every request',
                'Implement proper authorization checks'
            ],
            'Security_Headers': [
                'Implement HTTP Strict Transport Security (HSTS)',
                'Configure X-Frame-Options header',
                'Set X-Content-Type-Options header',
                'Implement Content Security Policy'
            ]
        }
