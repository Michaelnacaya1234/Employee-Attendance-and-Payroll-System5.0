# Password Reset System Setup Guide

## Overview
This system allows users to reset their passwords using a 6-digit code sent via email using PHPMailer and Gmail SMTP.

## Features
- ✅ 6-digit numeric reset codes (instead of long tokens)
- ✅ Email delivery via Gmail SMTP using PHPMailer
- ✅ 15-minute code expiry for security
- ✅ Rate limiting (max 3 attempts per hour per IP)
- ✅ Password strength indicator
- ✅ Two-step process: request code → enter code + new password
- ✅ Remember me functionality
- ✅ Secure password hashing

## Prerequisites
1. **PHPMailer**: Download from [PHPMailer GitHub](https://github.com/PHPMailer/PHPMailer)
2. **Gmail Account**: With 2-factor authentication enabled
3. **Gmail App Password**: Generated for this application

## Installation Steps

### 1. Install PHPMailer
```bash
# Download PHPMailer to your project root
# Extract and ensure the folder structure is:
# /your-project/
# ├── phpmailer-master/
# │   └── src/
# │       ├── Exception.php
# │       ├── PHPMailer.php
# │       └── SMTP.php
```

### 2. Configure Gmail
1. **Enable 2-Factor Authentication** on your Gmail account
2. **Generate App Password**:
   - Go to Google Account settings
   - Security → 2-Step Verification → App passwords
   - Generate password for "Mail"
   - Copy the 16-character password

### 3. Update Email Configuration
Edit `api/email-config.php`:
```php
// Replace these values with your actual Gmail credentials
define('SMTP_USERNAME', 'your-actual-email@gmail.com');
define('SMTP_PASSWORD', 'your-16-char-app-password');
define('SMTP_FROM_EMAIL', 'your-actual-email@gmail.com');
define('SMTP_FROM_NAME', 'Your Actual Company Name');
```

### 4. Database Setup
Run the updated `database.sql` to add the new fields:
```sql
ALTER TABLE users 
ADD COLUMN reset_code VARCHAR(6) DEFAULT NULL,
ADD COLUMN reset_code_expires DATETIME DEFAULT NULL;
```

## How It Works

### Step 1: User Requests Reset Code
1. User clicks "Forgot Password?" on login page
2. Enters username/email
3. System generates 6-digit code
4. Code is stored in database with 15-minute expiry
5. Code is sent via email using PHPMailer

### Step 2: User Enters Code and New Password
1. User receives email with 6-digit code
2. Returns to forgot password page
3. Enters the 6-digit code
4. Sets new password with confirmation
5. Password is updated and code is cleared

## Security Features

- **Rate Limiting**: Max 3 attempts per hour per IP
- **Code Expiry**: 15-minute automatic expiry
- **Secure Generation**: Random 6-digit codes
- **No User Enumeration**: Same response for existing/non-existing users
- **Password Validation**: Minimum 6 characters required
- **Secure Hashing**: Passwords stored using PHP's password_hash()

## File Structure
```
├── master/
│   ├── login.html (updated with forgot password link)
│   └── forgot-password.html (new two-step form)
├── js/
│   ├── login.js (updated with remember me)
│   └── forgot-password.js (new two-step logic)
├── api/
│   ├── auth.php (updated with new operations)
│   ├── email-config.php (new email configuration)
│   └── connection-pdo.php (existing)
└── phpmailer-master/ (PHPMailer library)
```

## Testing

### Test the System
1. **Login Page**: Click "Forgot Password?" link
2. **Request Code**: Enter username/email
3. **Check Email**: Verify code is received
4. **Reset Password**: Enter code and new password
5. **Login**: Try logging in with new password

### Common Issues
- **Email not sending**: Check Gmail credentials and app password
- **Code expired**: Codes expire after 15 minutes
- **Rate limited**: Wait 1 hour after 3 failed attempts
- **PHPMailer errors**: Ensure PHPMailer files are in correct location

## Customization

### Change Code Expiry
Edit `api/email-config.php`:
```php
define('CODE_EXPIRY_MINUTES', 30); // Change to 30 minutes
```

### Change Rate Limiting
Edit `api/email-config.php`:
```php
define('MAX_RESET_ATTEMPTS', 5); // Allow 5 attempts
define('RATE_LIMIT_HOURS', 2);   // Reset after 2 hours
```

### Customize Email Template
Edit the email HTML in `api/auth.php` function `sendResetCodeEmail()`.

## Production Considerations

1. **Remove Debug Info**: Don't expose internal errors to users
2. **Use Environment Variables**: Store email credentials securely
3. **Enable HTTPS**: Ensure all communications are encrypted
4. **Monitor Logs**: Watch for abuse patterns
5. **Backup Strategy**: Ensure user data is backed up

## Support
For issues or questions, check:
- PHPMailer documentation
- Gmail SMTP settings
- PHP error logs
- Database connection status
