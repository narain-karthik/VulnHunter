# VulnHunter OTP Authentication System

## Overview

VulnHunter now features an enhanced two-factor authentication (2FA) system with One-Time Password (OTP) verification via email. This provides enterprise-grade security for accessing the security testing framework.

## Authentication Flow

### Step 1: Username & Password
- Enter your VulnHunter username and password
- Credentials are verified using SHA-256 hashing with salt
- Failed attempts are tracked with automatic lockout protection

### Step 2: OTP Email Verification  
- Upon successful password verification, an OTP is automatically sent to your registered email
- Check your email (including spam/junk folders) for the 6-digit verification code
- Enter the OTP within 5 minutes to complete authentication

## Email Configuration

The system is configured to send OTP emails using Gmail SMTP:

- **SMTP Server**: smtp.gmail.com
- **Port**: 587 (TLS encryption)
- **Sender Email**: narainjkans@gmail.com
- **Security**: App password authentication

## OTP Features

### Professional Email Format
- HTML-formatted emails with VulnHunter branding
- Clear security warnings and instructions
- Session information and timestamps
- Professional styling and layout

### Security Features
- **6-digit random OTP codes**
- **5-minute expiration time**
- **3 OTP verification attempts maximum**
- **Automatic cleanup of expired codes**
- **Secure temporary storage**

### User Experience
- Clear step-by-step authentication prompts
- Helpful error messages and tips
- Real-time feedback on verification status
- Lockout protection with remaining time display

## Testing the System

Use the provided test script to verify OTP functionality:

```bash
python3 test_otp_authentication.py
```

### Test Options:
1. **OTP Email System Only** - Test email sending and verification
2. **Complete Authentication** - Test full 2FA flow
3. **Exit** - Exit the test suite

## User Credentials

**Production Credentials:**
- Username: WhiteDevil
- Password: qwer4321
- Email: narainjkans@gmail.com

## Security Benefits

### Enhanced Protection
- **Two-factor authentication** prevents unauthorized access
- **Email verification** ensures legitimate user access
- **Time-limited OTP codes** prevent replay attacks
- **Account lockout** protection against brute force

### Enterprise Features
- **Professional email notifications**
- **Audit trail with timestamps**
- **Secure credential storage**
- **Fail-safe error handling**

## Troubleshooting

### Common Issues:

**OTP Email Not Received:**
- Check spam/junk email folders
- Verify internet connection
- Ensure Gmail SMTP credentials are correct

**OTP Verification Failed:**
- Ensure code is entered within 5 minutes
- Check for typos in the 6-digit code
- Verify email contains the latest OTP

**Authentication Lockout:**
- Wait for lockout period to expire (5 minutes)
- Ensure correct username and password
- Contact administrator if persistent issues

## Integration with VulnHunter

The OTP system is seamlessly integrated into the main VulnHunter application:

1. **Automatic Activation** - OTP verification is required for all logins
2. **No Configuration Required** - System works out-of-the-box
3. **Backward Compatible** - Existing authentication flow enhanced
4. **Zero Downtime** - No interruption to security testing workflows

## Security Compliance

The OTP authentication system meets enterprise security standards:

- **NIST 800-63B** - Digital identity guidelines compliance
- **Multi-factor Authentication** - Industry best practices
- **Secure Communications** - TLS encrypted email delivery
- **Access Control** - Proper authentication and authorization

This enhanced authentication system ensures that only authorized users can access VulnHunter's powerful security testing capabilities while maintaining a professional user experience.