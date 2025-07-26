#!/usr/bin/env python3
"""
Test script for VulnHunter OTP Authentication System
Demonstrates the enhanced two-factor authentication with email OTP
"""

import sys
import os
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def test_otp_system():
    """Test the OTP email system independently"""
    try:
        from auth.otp_email import OTPEmailSystem
        
        print(f"{Fore.CYAN}{'=' * 60}")
        print(f"{Fore.CYAN}    VulnHunter OTP Email System Test")
        print(f"{Fore.CYAN}{'=' * 60}")
        print()
        
        otp_system = OTPEmailSystem()
        
        print(f"{Fore.YELLOW}Testing OTP email generation and sending...")
        # Use masked email for display
        test_email = otp_system._decode_email()
        masked_email = otp_system._mask_email(test_email)
        print(f"{Fore.WHITE}Target Email: {masked_email}")
        print(f"{Fore.WHITE}Username: WhiteDevil")
        print()
        
        # Send test OTP
        success = otp_system.send_otp_email(test_email, "WhiteDevil")
        
        if success:
            print(f"{Fore.GREEN}✅ OTP email sent successfully!")
            print(f"{Fore.CYAN}📧 Check your email for the 6-digit verification code")
            print()
            
            # Simulate OTP verification
            while True:
                try:
                    otp_code = input(f"{Fore.GREEN}Enter OTP to test verification (or 'skip' to exit): {Style.RESET_ALL}").strip()
                    
                    if otp_code.lower() == 'skip':
                        print(f"{Fore.YELLOW}OTP verification test skipped.")
                        break
                    
                    if len(otp_code) == 6 and otp_code.isdigit():
                        success, message = otp_system.verify_otp("WhiteDevil", otp_code)
                        if success:
                            print(f"{Fore.GREEN}✅ {message}")
                        else:
                            print(f"{Fore.RED}❌ {message}")
                        break
                    else:
                        print(f"{Fore.RED}❌ Please enter a valid 6-digit OTP code.")
                        
                except KeyboardInterrupt:
                    print(f"\n{Fore.YELLOW}Test cancelled.")
                    break
        else:
            print(f"{Fore.RED}❌ Failed to send OTP email.")
            print(f"{Fore.YELLOW}This could be due to network issues or SMTP configuration.")
            
    except ImportError as e:
        print(f"{Fore.RED}❌ Error importing OTP system: {str(e)}")
        print(f"{Fore.YELLOW}Make sure the auth module is properly installed.")
    except Exception as e:
        print(f"{Fore.RED}❌ OTP test error: {str(e)}")
        
def test_complete_authentication():
    """Test the complete authentication flow"""
    try:
        from auth.authentication import VulnHunterAuth
        
        print(f"{Fore.CYAN}{'=' * 60}")
        print(f"{Fore.CYAN}    VulnHunter Complete 2FA Authentication Test")
        print(f"{Fore.CYAN}{'=' * 60}")
        print()
        
        auth_system = VulnHunterAuth()
        
        print(f"{Fore.YELLOW}Testing complete two-factor authentication...")
        print(f"{Fore.WHITE}Username: WhiteDevil")
        print(f"{Fore.WHITE}This will test the full login process including OTP verification.")
        print()
        
        # Run authentication
        success = auth_system.authenticate()
        
        if success:
            print(f"{Fore.GREEN}✅ Complete authentication test successful!")
            print(f"{Fore.CYAN}Authentication system is working correctly.")
        else:
            print(f"{Fore.RED}❌ Authentication test failed.")
            print(f"{Fore.YELLOW}Please check credentials and email configuration.")
            
    except ImportError as e:
        print(f"{Fore.RED}❌ Error importing authentication system: {str(e)}")
        print(f"{Fore.YELLOW}Make sure the auth module is properly installed.")
    except Exception as e:
        print(f"{Fore.RED}❌ Authentication test error: {str(e)}")

def main():
    """Main test menu"""
    print(f"{Fore.MAGENTA}{'=' * 70}")
    print(f"{Fore.MAGENTA}         VulnHunter OTP Authentication Test Suite")
    print(f"{Fore.MAGENTA}{'=' * 70}")
    print()
    
    while True:
        print(f"{Fore.WHITE}Available Tests:")
        print(f"{Fore.CYAN}1. {Fore.WHITE}OTP Email System Only")
        print(f"{Fore.CYAN}2. {Fore.WHITE}Complete Authentication Flow")
        print(f"{Fore.CYAN}3. {Fore.WHITE}Exit")
        print()
        
        try:
            choice = input(f"{Fore.GREEN}Select test option (1-3): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                print()
                test_otp_system()
                print()
            elif choice == '2':
                print()
                test_complete_authentication()
                print()
            elif choice == '3':
                print(f"{Fore.YELLOW}Exiting test suite...")
                break
            else:
                print(f"{Fore.RED}❌ Invalid option. Please select 1-3.")
                print()
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Test suite cancelled.")
            break
        except Exception as e:
            print(f"{Fore.RED}❌ Error: {str(e)}")
            print()

if __name__ == "__main__":
    main()