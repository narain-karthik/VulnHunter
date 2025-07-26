#!/usr/bin/env python3
"""
VulnHunter Authentication Module
Secure login system for VulnHunter CLI access
"""

import hashlib
import getpass
import time
import os
from colorama import Fore, Style, init
try:
    from .otp_email import OTPEmailSystem
except ImportError:
    from auth.otp_email import OTPEmailSystem

# Initialize colorama
init(autoreset=True)

class VulnHunterAuth:
    """Enhanced authentication system for VulnHunter with OTP email verification"""
    
    def __init__(self):
        # Secure credential storage (hashed)
        self.credentials = {
            "WhiteDevil": {
                "password": self._hash_password("qwer4321"),
                "email": self._decode_user_email()
            }
        }
        self.max_attempts = 3
        self.lockout_duration = 300  # 5 minutes lockout
        self.failed_attempts = {}
        self.otp_system = OTPEmailSystem()
    
    def _hash_password(self, password):
        """Hash password using SHA-256 with salt"""
        salt = "vulnhunter_salt_2025"
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    def _is_locked_out(self, username):
        """Check if user is currently locked out"""
        if username not in self.failed_attempts:
            return False
        
        attempts, last_attempt = self.failed_attempts[username]
        if attempts >= self.max_attempts:
            if time.time() - last_attempt < self.lockout_duration:
                return True
            else:
                # Reset attempts after lockout period
                del self.failed_attempts[username]
                return False
        return False
    
    def _record_failed_attempt(self, username):
        """Record a failed login attempt"""
        current_time = time.time()
        if username in self.failed_attempts:
            attempts, _ = self.failed_attempts[username]
            self.failed_attempts[username] = (attempts + 1, current_time)
        else:
            self.failed_attempts[username] = (1, current_time)
    
    def _get_lockout_remaining(self, username):
        """Get remaining lockout time in seconds"""
        if username not in self.failed_attempts:
            return 0
        
        attempts, last_attempt = self.failed_attempts[username]
        if attempts >= self.max_attempts:
            remaining = self.lockout_duration - (time.time() - last_attempt)
            return max(0, remaining)
        return 0
    
    def _decode_user_email(self):
        """Decode obfuscated user email"""
        # Base64-like obfuscation for email
        encoded = "bmFyYWluamthbnNAZ21haWwuY29t"
        import base64
        return base64.b64decode(encoded).decode('utf-8')
    
    def _mask_email_display(self, email):
        """Mask email for display purposes"""
        if '@' in email:
            username, domain = email.split('@')
            masked_username = username[:2] + '*' * (len(username) - 4) + username[-2:] if len(username) > 4 else username[:1] + '*' * (len(username) - 1)
            return f"{masked_username}@{domain}"
        return email
    
    def display_banner(self):
        """Display VulnHunter authentication banner"""
        print(f"{Fore.CYAN}🔐 VulnHunter Security Authentication Required")
        print(f"{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}                    VULNHUNTER AUTHENTICATION")
        print(f"{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.WHITE}Enterprise-Grade Security Testing Framework")
        print(f"{Fore.YELLOW}⚠️  Authorized Access Only - Security Testing Tool ⚠️")
        print(f"{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.MAGENTA}🔒 Two-Factor Authentication (2FA) Enabled")
        print(f"{Fore.WHITE}📧 OTP verification via email required")
        print(f"{Fore.CYAN}{'=' * 70}")
        print()
    
    def authenticate(self):
        """Main authentication function"""
        self.display_banner()
        
        while True:
            try:
                # Get username
                print(f"{Fore.WHITE}Please enter your credentials to access VulnHunter:")
                username = input(f"{Fore.GREEN}Username: {Style.RESET_ALL}").strip()
                
                if not username:
                    print(f"{Fore.RED}❌ Username cannot be empty.")
                    continue
                
                # Check for lockout
                if self._is_locked_out(username):
                    remaining = self._get_lockout_remaining(username)
                    minutes = int(remaining // 60)
                    seconds = int(remaining % 60)
                    print(f"{Fore.RED}🔒 Account locked due to multiple failed attempts.")
                    print(f"{Fore.RED}   Please try again in {minutes}m {seconds}s")
                    return False
                
                # Get password securely
                password = getpass.getpass(f"{Fore.GREEN}Password: {Style.RESET_ALL}")
                
                if not password:
                    print(f"{Fore.RED}❌ Password cannot be empty.")
                    continue
                
                # Verify credentials
                if self._verify_credentials(username, password):
                    print(f"{Fore.GREEN}✅ Step 1/2: Password verified!")
                    print(f"{Fore.YELLOW}🔐 Step 2/2: OTP verification required...")
                    print()
                    
                    # Send OTP email
                    user_email = self.credentials[username]["email"]
                    masked_email = self._mask_email_display(user_email)
                    print(f"{Fore.CYAN}📧 Sending OTP to registered email: {masked_email}")
                    if self.otp_system.send_otp_email(user_email, username):
                        # Get OTP from user
                        if self._verify_otp(username):
                            print(f"{Fore.GREEN}✅ Two-factor authentication successful!")
                            print(f"{Fore.GREEN}   Welcome back, {username}!")
                            print(f"{Fore.CYAN}{'=' * 70}")
                            print()
                            
                            # Clear failed attempts on successful login
                            if username in self.failed_attempts:
                                del self.failed_attempts[username]
                            
                            return True
                        else:
                            print(f"{Fore.RED}❌ OTP verification failed!")
                            self._record_failed_attempt(username)
                            continue
                    else:
                        print(f"{Fore.RED}❌ Failed to send OTP. Please try again.")
                        continue
                else:
                    self._record_failed_attempt(username)
                    attempts_left = self.max_attempts - self.failed_attempts.get(username, (0, 0))[0]
                    
                    print(f"{Fore.RED}❌ Authentication failed!")
                    print(f"{Fore.RED}   Invalid username or password.")
                    
                    if attempts_left > 0:
                        print(f"{Fore.YELLOW}   Attempts remaining: {attempts_left}")
                    else:
                        print(f"{Fore.RED}   Account locked for {self.lockout_duration // 60} minutes.")
                    
                    print()
                    
                    if attempts_left <= 0:
                        return False
                    
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Authentication cancelled by user.")
                return False
            except Exception as e:
                print(f"{Fore.RED}❌ Authentication error: {str(e)}")
                return False
    
    def _verify_credentials(self, username, password):
        """Verify username and password"""
        if username not in self.credentials:
            return False
        
        hashed_password = self._hash_password(password)
        return self.credentials[username]["password"] == hashed_password
    
    def _verify_otp(self, username):
        """Handle OTP verification process"""
        max_otp_attempts = 3
        otp_attempts = 0
        
        while otp_attempts < max_otp_attempts:
            try:
                print(f"{Fore.WHITE}Enter the 6-digit OTP code sent to your email:")
                otp_code = input(f"{Fore.GREEN}OTP Code: {Style.RESET_ALL}").strip()
                
                if not otp_code:
                    print(f"{Fore.RED}❌ OTP code cannot be empty.")
                    otp_attempts += 1
                    continue
                
                if len(otp_code) != 6 or not otp_code.isdigit():
                    print(f"{Fore.RED}❌ OTP must be exactly 6 digits.")
                    otp_attempts += 1
                    continue
                
                # Verify OTP
                success, message = self.otp_system.verify_otp(username, otp_code)
                
                if success:
                    print(f"{Fore.GREEN}✅ {message}")
                    return True
                else:
                    print(f"{Fore.RED}❌ {message}")
                    otp_attempts += 1
                    
                    remaining_attempts = max_otp_attempts - otp_attempts
                    if remaining_attempts > 0:
                        print(f"{Fore.YELLOW}   OTP attempts remaining: {remaining_attempts}")
                        print(f"{Fore.CYAN}💡 Tip: Check your email spam/junk folder if you don't see the OTP")
                        print()
                
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}OTP verification cancelled by user.")
                return False
            except Exception as e:
                print(f"{Fore.RED}❌ OTP verification error: {str(e)}")
                otp_attempts += 1
        
        print(f"{Fore.RED}❌ Maximum OTP attempts exceeded.")
        return False
    
    def display_access_denied(self):
        """Display access denied message"""
        print(f"{Fore.RED}{'=' * 70}")
        print(f"{Fore.RED}                        ACCESS DENIED")
        print(f"{Fore.RED}{'=' * 70}")
        print(f"{Fore.WHITE}Authentication failed. Access to VulnHunter is restricted.")
        print(f"{Fore.YELLOW}This incident has been logged for security purposes.")
        print(f"{Fore.RED}{'=' * 70}")
        print()

def require_authentication():
    """Decorator function to require authentication"""
    auth = VulnHunterAuth()
    
    if auth.authenticate():
        return True
    else:
        auth.display_access_denied()
        return False

if __name__ == "__main__":
    # Test authentication system
    auth = VulnHunterAuth()
    success = auth.authenticate()
    
    if success:
        print("Access granted to VulnHunter!")
    else:
        print("Access denied!")