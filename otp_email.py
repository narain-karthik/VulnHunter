#!/usr/bin/env python3
"""
VulnHunter OTP Email Module
SMTP-based One-Time Password system for enhanced security
"""

import smtplib
import random
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from colorama import Fore, Style

class OTPEmailSystem:
    """OTP email verification system using SMTP"""
    
    def __init__(self):
        # SMTP Configuration
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        # Email credentials (obfuscated for security)
        self.sender_email = self._decode_email()
        self.sender_password = self._decode_password()
        
        # OTP Configuration
        self.otp_length = 6
        self.otp_validity = 300  # 5 minutes
        self.active_otps = {}  # Store OTP data temporarily
    
    def _decode_email(self):
        """Decode obfuscated email address"""
        # Base64-like obfuscation for email
        encoded = "bmFyYWluamthbnNAZ21haWwuY29t"
        import base64
        return base64.b64decode(encoded).decode('utf-8')
    
    def _decode_password(self):
        """Decode obfuscated app password"""
        # Simple XOR obfuscation for password
        encoded = [102, 110, 98, 117, 37, 96, 97, 112, 102, 37, 119, 117, 124, 100, 37, 111, 103, 114, 105]
        key = 5
        return ''.join(chr(c ^ key) for c in encoded)
    
    def _mask_email(self, email):
        """Mask email address for display purposes"""
        if '@' in email:
            username, domain = email.split('@')
            masked_username = username[:2] + '*' * (len(username) - 4) + username[-2:] if len(username) > 4 else username[:1] + '*' * (len(username) - 1)
            return f"{masked_username}@{domain}"
        return email
        
    def generate_otp(self):
        """Generate a random 6-digit OTP"""
        return ''.join([str(random.randint(0, 9)) for _ in range(self.otp_length)])
    
    def create_email_content(self, otp, username):
        """Create professional email content for OTP"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                .header {{
                    text-align: center;
                    color: #2c3e50;
                    border-bottom: 2px solid #3498db;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }}
                .otp-code {{
                    background-color: #ecf0f1;
                    font-size: 32px;
                    font-weight: bold;
                    color: #2c3e50;
                    text-align: center;
                    padding: 20px;
                    border-radius: 8px;
                    letter-spacing: 5px;
                    margin: 20px 0;
                    border: 2px dashed #3498db;
                }}
                .warning {{
                    background-color: #fff3cd;
                    border: 1px solid #ffeaa7;
                    color: #856404;
                    padding: 15px;
                    border-radius: 5px;
                    margin: 20px 0;
                }}
                .footer {{
                    text-align: center;
                    color: #7f8c8d;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #ecf0f1;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 VulnHunter Security Verification</h1>
                    <p>Enterprise-Grade Security Testing Framework</p>
                </div>
                
                <h2>Hello {username},</h2>
                <p>A login attempt has been detected for your VulnHunter account. To complete the authentication process, please use the following One-Time Password (OTP):</p>
                
                <div class="otp-code">{otp}</div>
                
                <div class="warning">
                    <strong>⚠️ Security Notice:</strong>
                    <ul>
                        <li>This OTP is valid for <strong>5 minutes only</strong></li>
                        <li>Never share this code with anyone</li>
                        <li>If you did not initiate this login, please secure your account immediately</li>
                    </ul>
                </div>
                
                <p><strong>Session Information:</strong></p>
                <ul>
                    <li>Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</li>
                    <li>Application: VulnHunter Security Testing Framework</li>
                    <li>Authentication Level: Two-Factor Authentication</li>
                </ul>
                
                <div class="footer">
                    <p>VulnHunter Security Framework - Authorized Access Only</p>
                    <p>This is an automated security message. Do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        return html_content
    
    def send_otp_email(self, recipient_email, username):
        """Send OTP via email and return the OTP for verification"""
        try:
            # Generate OTP
            otp = self.generate_otp()
            
            # Store OTP with timestamp
            self.active_otps[username] = {
                'otp': otp,
                'timestamp': time.time(),
                'email': recipient_email
            }
            
            # Create email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"🔐 VulnHunter Security Code: {otp}"
            msg['From'] = self.sender_email
            msg['To'] = recipient_email
            
            # Create HTML content
            html_content = self.create_email_content(otp, username)
            html_part = MIMEText(html_content, 'html')
            msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
            
            masked_email = self._mask_email(recipient_email)
            print(f"{Fore.GREEN}✅ OTP sent successfully to {masked_email}")
            print(f"{Fore.YELLOW}📧 Please check your email for the 6-digit verification code")
            print(f"{Fore.CYAN}⏰ Code expires in 5 minutes")
            
            return True
            
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to send OTP email: {str(e)}")
            print(f"{Fore.YELLOW}⚠️  Please check your internet connection and try again")
            return False
    
    def verify_otp(self, username, entered_otp):
        """Verify the entered OTP"""
        if username not in self.active_otps:
            return False, "No OTP found for this user"
        
        otp_data = self.active_otps[username]
        
        # Check if OTP has expired
        if time.time() - otp_data['timestamp'] > self.otp_validity:
            del self.active_otps[username]
            return False, "OTP has expired. Please request a new one"
        
        # Verify OTP
        if entered_otp == otp_data['otp']:
            del self.active_otps[username]  # Remove used OTP
            return True, "OTP verified successfully"
        else:
            return False, "Invalid OTP. Please try again"
    
    def cleanup_expired_otps(self):
        """Remove expired OTPs from memory"""
        current_time = time.time()
        expired_users = []
        
        for username, otp_data in self.active_otps.items():
            if current_time - otp_data['timestamp'] > self.otp_validity:
                expired_users.append(username)
        
        for username in expired_users:
            del self.active_otps[username]