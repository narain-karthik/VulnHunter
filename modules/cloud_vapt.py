"""
Cloud VAPT Module - Cloud infrastructure security testing
Specialized module for cloud environment vulnerability assessment and penetration testing
"""

from colorama import Fore, Style

class CloudVAPT:
    def __init__(self):
        self.vapt_type = "cloud"
        
    def get_default_objectives(self):
        """Get default objectives for cloud VAPT"""
        return [
            "Assess cloud infrastructure configuration security",
            "Evaluate cloud identity and access management (IAM)",
            "Test cloud storage security and access controls",
            "Assess cloud network security and segmentation",
            "Evaluate cloud service configurations",
            "Test for cloud-specific vulnerabilities and misconfigurations",
            "Assess cloud logging and monitoring capabilities",
            "Evaluate data protection and encryption in cloud",
            "Test cloud API security and authentication",
            "Assess compliance with cloud security best practices"
        ]
        
    def get_default_scope(self, target):
        """Get default scope for cloud VAPT"""
        return {
            'target_cloud_environment': target,
            'inclusions': [
                'Cloud infrastructure components',
                'Cloud storage services',
                'Cloud identity and access management',
                'Cloud network configurations',
                'Cloud-hosted applications and services',
                'Cloud API endpoints',
                'Cloud logging and monitoring systems'
            ],
            'exclusions': [
                'Production data modification',
                'Service disruption testing',
                'Third-party cloud services (without authorization)',
                'Other tenants in shared environments'
            ],
            'constraints': [
                'Read-only access where possible',
                'No impact to business-critical services',
                'Compliance with cloud provider terms of service',
                'Respect for shared responsibility model'
            ]
        }
        
    def get_default_methodology(self):
        """Get default methodology for cloud VAPT"""
        return "Cloud Security Alliance (CSA) Cloud Controls Matrix"
        
    def get_default_tools(self):
        """Get default tools for cloud VAPT"""
        return [
            'aws_cli', 'azure_cli', 'gcloud', 'scout_suite', 'cloudsploit',
            'prowler', 'cloud_mapper', 'pacu', 'cloud_nuke', 'steampipe'
        ]
        
    def get_available_tools(self):
        """Get available tools with descriptions"""
        return {
            'scout_suite': 'Multi-cloud security auditing tool',
            'prowler': 'AWS security assessment tool',
            'cloudsploit': 'Cloud security configuration scanner',
            'cloud_mapper': 'AWS environment mapping and visualization',
            'pacu': 'AWS penetration testing toolkit',
            'azure_cli': 'Azure command-line interface for security assessment',
            'aws_cli': 'AWS command-line interface for security assessment',
            'gcloud': 'Google Cloud command-line interface',
            'cloud_nuke': 'Tool for cleaning up cloud resources',
            'steampipe': 'Cloud resource querying and analysis',
            'cartography': 'Cloud asset inventory and analysis',
            'cloud_custodian': 'Cloud security and governance',
            'terrascan': 'Infrastructure as Code security scanner',
            'checkov': 'Static analysis for cloud infrastructure'
        }
        
    def get_vulnerability_tools(self):
        """Get vulnerability assessment tools specific to cloud testing"""
        return {
            'scout_suite': 'Comprehensive multi-cloud security assessment',
            'prowler': 'AWS security best practices assessment',
            'cloudsploit': 'Cloud configuration vulnerability scanner',
            'custom_checks': 'Custom cloud security checks',
            'policy_analyzer': 'Cloud IAM policy analysis',
            'bucket_finder': 'Cloud storage bucket enumeration',
            'cloud_enum': 'Cloud service enumeration',
            'cloud_brute': 'Cloud resource brute forcing',
            'iam_analyzer': 'Cloud IAM configuration analysis'
        }
        
    def get_available_exploits(self):
        """Get available exploits for cloud testing"""
        return [
            {
                'name': 'Public Cloud Storage Enumeration',
                'description': 'Enumerate publicly accessible cloud storage buckets',
                'type': 'cloud_storage_enum',
                'targets': ['s3', 'azure_blob', 'gcs'],
                'risk_level': 'medium',
                'safe_for_automation': True
            },
            {
                'name': 'Cloud Metadata Service Access',
                'description': 'Test access to cloud instance metadata services',
                'type': 'metadata_service_access',
                'targets': ['ec2', 'azure_vm', 'gce'],
                'risk_level': 'high',
                'safe_for_automation': True
            },
            {
                'name': 'IAM Policy Privilege Escalation',
                'description': 'Test for IAM policy misconfigurations allowing privilege escalation',
                'type': 'iam_privilege_escalation',
                'targets': ['iam', 'azure_ad', 'gcp_iam'],
                'risk_level': 'high',
                'safe_for_automation': False
            },
            {
                'name': 'Cloud API Key Enumeration',
                'description': 'Enumerate and test cloud API keys',
                'type': 'api_key_enum',
                'targets': ['aws_keys', 'azure_keys', 'gcp_keys'],
                'risk_level': 'high',
                'safe_for_automation': False
            },
            {
                'name': 'Cloud Function Vulnerability Test',
                'description': 'Test serverless functions for vulnerabilities',
                'type': 'serverless_vuln_test',
                'targets': ['lambda', 'azure_functions', 'cloud_functions'],
                'risk_level': 'medium',
                'safe_for_automation': True
            },
            {
                'name': 'Cloud Database Access Test',
                'description': 'Test cloud database access controls',
                'type': 'cloud_db_access',
                'targets': ['rds', 'azure_sql', 'cloud_sql'],
                'risk_level': 'high',
                'safe_for_automation': False
            },
            {
                'name': 'Container Registry Enumeration',
                'description': 'Enumerate container registries and images',
                'type': 'container_registry_enum',
                'targets': ['ecr', 'acr', 'gcr'],
                'risk_level': 'medium',
                'safe_for_automation': True
            },
            {
                'name': 'Cloud Network Security Group Test',
                'description': 'Test cloud network security group configurations',
                'type': 'network_sg_test',
                'targets': ['security_groups', 'network_acls', 'firewall_rules'],
                'risk_level': 'medium',
                'safe_for_automation': True
            }
        ]
        
    def get_reconnaissance_methods(self):
        """Get reconnaissance methods specific to cloud testing"""
        return {
            'passive': [
                'Cloud service provider identification',
                'Public cloud resource enumeration via DNS',
                'Certificate transparency log analysis for cloud domains',
                'Search engine reconnaissance for cloud resources',
                'Social media and job posting analysis for cloud usage',
                'GitHub and code repository analysis for cloud configurations',
                'Public cloud storage bucket enumeration',
                'Cloud API endpoint discovery'
            ],
            'active': [
                'Cloud service fingerprinting',
                'Cloud storage bucket brute forcing',
                'Cloud API enumeration and testing',
                'Cloud metadata service probing',
                'Cloud container registry enumeration',
                'Cloud function discovery and testing',
                'Cloud database service enumeration',
                'Cloud network topology mapping',
                'Cloud IAM user and role enumeration'
            ]
        }
        
    def get_vulnerability_categories(self):
        """Get vulnerability categories for cloud testing"""
        return [
            'Cloud Identity and Access Management (IAM) Misconfigurations',
            'Cloud Storage Security Issues',
            'Cloud Network Security Misconfigurations',
            'Cloud Database Security Vulnerabilities',
            'Serverless Function Security Issues',
            'Container and Orchestration Security Problems',
            'Cloud API Security Vulnerabilities',
            'Cloud Logging and Monitoring Gaps',
            'Data Protection and Encryption Issues',
            'Cloud Compliance and Governance Failures',
            'Cloud Service Configuration Errors',
            'Cloud Key Management Issues'
        ]
        
    def get_testing_phases(self):
        """Get specific testing phases for cloud VAPT"""
        return [
            {
                'phase': 'Cloud Asset Discovery',
                'description': 'Identify and enumerate cloud assets and services',
                'tools': ['cloud_enum', 'dns_recon', 'certificate_transparency'],
                'duration': '2-3 hours'
            },
            {
                'phase': 'Cloud Configuration Assessment',
                'description': 'Assess cloud service configurations for security issues',
                'tools': ['scout_suite', 'prowler', 'cloudsploit'],
                'duration': '4-6 hours'
            },
            {
                'phase': 'IAM and Access Control Testing',
                'description': 'Test identity and access management configurations',
                'tools': ['iam_analyzer', 'policy_analyzer', 'custom_scripts'],
                'duration': '3-4 hours'
            },
            {
                'phase': 'Cloud Storage Security Testing',
                'description': 'Test cloud storage security and access controls',
                'tools': ['bucket_finder', 'cloud_storage_enum', 'custom_tools'],
                'duration': '2-3 hours'
            },
            {
                'phase': 'Cloud Network Security Testing',
                'description': 'Test cloud network security configurations',
                'tools': ['network_analyzer', 'security_group_analyzer'],
                'duration': '2-4 hours'
            },
            {
                'phase': 'Cloud Service Exploitation',
                'description': 'Attempt to exploit identified cloud vulnerabilities',
                'tools': ['pacu', 'cloud_exploitation_tools'],
                'duration': '4-8 hours'
            }
        ]
        
    def get_cloud_providers(self):
        """Get supported cloud providers and their specific testing approaches"""
        return {
            'AWS': {
                'services': [
                    'EC2', 'S3', 'RDS', 'Lambda', 'IAM', 'VPC', 'CloudFront',
                    'ELB', 'Route53', 'CloudTrail', 'CloudWatch', 'KMS'
                ],
                'tools': ['prowler', 'pacu', 'cloud_mapper', 'aws_cli'],
                'key_areas': ['IAM policies', 'S3 bucket permissions', 'Security groups', 'CloudTrail logging']
            },
            'Azure': {
                'services': [
                    'Virtual Machines', 'Blob Storage', 'SQL Database', 'Azure Functions',
                    'Azure AD', 'Virtual Network', 'Application Gateway', 'Key Vault'
                ],
                'tools': ['scout_suite', 'azure_cli', 'cloudsploit'],
                'key_areas': ['Azure AD configurations', 'Storage account access', 'Network security groups']
            },
            'GCP': {
                'services': [
                    'Compute Engine', 'Cloud Storage', 'Cloud SQL', 'Cloud Functions',
                    'IAM', 'VPC', 'Cloud Load Balancing', 'Cloud KMS'
                ],
                'tools': ['scout_suite', 'gcloud', 'cloudsploit'],
                'key_areas': ['IAM bindings', 'Storage bucket permissions', 'Firewall rules']
            }
        }
        
    def get_iam_testing_areas(self):
        """Get IAM testing areas for cloud environments"""
        return {
            'Policy_Analysis': [
                'Overly permissive policies',
                'Privilege escalation paths',
                'Cross-account access',
                'Resource-based policies'
            ],
            'User_Management': [
                'Inactive user accounts',
                'Shared user accounts',
                'Administrative privileges',
                'Access key management'
            ],
            'Role_Management': [
                'Cross-service roles',
                'External ID validation',
                'Role assumption policies',
                'Service roles'
            ],
            'Multi_Factor_Authentication': [
                'MFA enforcement',
                'MFA bypass methods',
                'MFA device management',
                'Emergency access procedures'
            ]
        }
        
    def get_cloud_storage_testing_areas(self):
        """Get cloud storage testing areas"""
        return {
            'Access_Controls': [
                'Public read/write permissions',
                'Authenticated user access',
                'Cross-account access',
                'Anonymous access'
            ],
            'Encryption': [
                'Data at rest encryption',
                'Data in transit encryption',
                'Key management',
                'Customer-managed keys'
            ],
            'Versioning_and_Lifecycle': [
                'Object versioning',
                'Lifecycle policies',
                'Backup and recovery',
                'Data retention'
            ],
            'Logging_and_Monitoring': [
                'Access logging',
                'Data access patterns',
                'Unusual access detection',
                'Compliance monitoring'
            ]
        }
        
    def get_serverless_testing_areas(self):
        """Get serverless function testing areas"""
        return [
            'Function permissions and roles',
            'Environment variable security',
            'Input validation and injection',
            'Resource access controls',
            'Event source security',
            'Cold start vulnerabilities',
            'Dependency vulnerabilities',
            'Logging and monitoring',
            'API Gateway configurations',
            'Container image security'
        ]
        
    def get_container_testing_areas(self):
        """Get container and orchestration testing areas"""
        return {
            'Container_Images': [
                'Base image vulnerabilities',
                'Package vulnerabilities',
                'Hardening configurations',
                'Secrets in images'
            ],
            'Registry_Security': [
                'Access controls',
                'Image scanning',
                'Vulnerability management',
                'Content trust'
            ],
            'Runtime_Security': [
                'Container escape techniques',
                'Privilege escalation',
                'Resource limitations',
                'Network segmentation'
            ],
            'Orchestration': [
                'Kubernetes API security',
                'RBAC configurations',
                'Pod security policies',
                'Network policies'
            ]
        }
        
    def get_compliance_frameworks(self):
        """Get cloud compliance frameworks and requirements"""
        return {
            'CIS_Benchmarks': [
                'CIS AWS Foundations Benchmark',
                'CIS Microsoft Azure Foundations Benchmark',
                'CIS Google Cloud Platform Foundation Benchmark'
            ],
            'SOC_2': [
                'Security principle controls',
                'Availability principle controls',
                'Processing integrity controls',
                'Confidentiality controls'
            ],
            'PCI_DSS': [
                'Network security requirements',
                'Data protection requirements',
                'Access control requirements',
                'Monitoring and testing requirements'
            ],
            'HIPAA': [
                'Administrative safeguards',
                'Physical safeguards',
                'Technical safeguards',
                'Breach notification requirements'
            ]
        }
        
    def get_risk_assessment_criteria(self):
        """Get risk assessment criteria for cloud vulnerabilities"""
        return {
            'Critical': [
                'Public cloud storage with sensitive data',
                'Administrative privilege escalation',
                'Cross-account access vulnerabilities',
                'Unencrypted sensitive data exposure'
            ],
            'High': [
                'IAM policy misconfigurations',
                'Network security group misconfigurations',
                'Weak encryption implementations',
                'Insufficient logging and monitoring'
            ],
            'Medium': [
                'Minor IAM privilege issues',
                'Non-critical configuration deviations',
                'Information disclosure vulnerabilities',
                'Compliance framework violations'
            ],
            'Low': [
                'Version disclosure',
                'Minor hardening issues',
                'Documentation and policy gaps',
                'Non-security impacting misconfigurations'
            ]
        }
        
    def validate_target(self, target):
        """Validate cloud target format"""
        import re
        
        # Cloud-specific patterns
        patterns = [
            r'^https?://.*\.amazonaws\.com.*',  # AWS
            r'^https?://.*\.azure\.com.*',      # Azure
            r'^https?://.*\.cloud\.google\.com.*',  # GCP
            r'^https?://.*\.s3.*\.amazonaws\.com.*',  # S3
            r'^https?://.*\.blob\.core\.windows\.net.*',  # Azure Blob
            r'^https?://.*\.storage\.googleapis\.com.*',  # GCS
            r'^[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]$',  # Generic cloud resource name
            r'^https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}.*'  # General URL
        ]
        
        return any(re.match(pattern, target) for pattern in patterns)
        
    def get_remediation_guidelines(self):
        """Get remediation guidelines for cloud security"""
        return {
            'IAM_Security': [
                'Implement principle of least privilege',
                'Enable multi-factor authentication',
                'Regular access reviews and cleanup',
                'Use role-based access control'
            ],
            'Data_Protection': [
                'Enable encryption at rest and in transit',
                'Implement proper key management',
                'Configure data loss prevention',
                'Regular data classification reviews'
            ],
            'Network_Security': [
                'Implement network segmentation',
                'Configure security groups with minimal access',
                'Enable VPC flow logs',
                'Use Web Application Firewalls'
            ],
            'Monitoring_Logging': [
                'Enable comprehensive audit logging',
                'Implement real-time monitoring',
                'Configure security alerting',
                'Regular log analysis and review'
            ],
            'Compliance': [
                'Regular compliance assessments',
                'Implement compliance automation',
                'Document security procedures',
                'Regular security training'
            ]
        }
