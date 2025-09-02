import re
import hashlib
import secrets
import string
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib

from ..config import settings

logger = logging.getLogger(__name__)

def validate_indian_mobile(mobile: str) -> bool:
    """Validate Indian mobile number format"""
    
    # Remove spaces and dashes
    clean_mobile = mobile.replace(' ', '').replace('-', '')
    
    # Indian mobile number pattern
    pattern = r'^(\+91|91)?[6-9]\d{9}$'
    
    return bool(re.match(pattern, clean_mobile))

def format_indian_mobile(mobile: str) -> str:
    """Format Indian mobile number to standard format (+91XXXXXXXXXX)"""
    
    # Remove spaces and dashes
    clean_mobile = mobile.replace(' ', '').replace('-', '')
    
    # Validate first
    if not validate_indian_mobile(clean_mobile):
        raise ValueError("Invalid Indian mobile number format")
    
    # Add +91 prefix if not present
    if not clean_mobile.startswith('+91'):
        if clean_mobile.startswith('91'):
            clean_mobile = '+' + clean_mobile
        else:
            clean_mobile = '+91' + clean_mobile
    
    return clean_mobile

def validate_email(email: str) -> bool:
    """Validate email format"""
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_name(name: str) -> bool:
    """Validate name format"""
    
    # Name should be 2-100 characters, only letters, spaces, and common punctuation
    if len(name.strip()) < 2 or len(name.strip()) > 100:
        return False
    
    pattern = r'^[a-zA-Z\s\.\-\']+$'
    return bool(re.match(pattern, name.strip()))

def generate_otp(length: int = 6) -> str:
    """Generate numeric OTP"""
    
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def generate_secure_token(length: int = 32) -> str:
    """Generate secure random token"""
    
    return secrets.token_urlsafe(length)

def hash_password(password: str) -> str:
    """Hash password using SHA-256 (Note: In production, use bcrypt or similar)"""
    
    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{password_hash}"

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    
    try:
        salt, password_hash = hashed_password.split(':')
        return hashlib.sha256((password + salt).encode()).hexdigest() == password_hash
    except ValueError:
        return False

def mask_mobile(mobile: str) -> str:
    """Mask mobile number for display (e.g., +91XXXXX67890)"""
    
    if len(mobile) < 8:
        return mobile
    
    if mobile.startswith('+91'):
        return f"+91XXXXX{mobile[-5:]}"
    elif mobile.startswith('91'):
        return f"91XXXXX{mobile[-5:]}"
    else:
        return f"XXXXX{mobile[-5:]}"

def mask_email(email: str) -> str:
    """Mask email for display (e.g., j***@example.com)"""
    
    try:
        username, domain = email.split('@')
        if len(username) <= 2:
            masked_username = username[0] + '*'
        else:
            masked_username = username[0] + '*' * (len(username) - 2) + username[-1]
        return f"{masked_username}@{domain}"
    except ValueError:
        return email

def extract_device_info(user_agent: str) -> Dict[str, str]:
    """Extract device information from User-Agent string"""
    
    device_info = {
        'browser': 'Unknown',
        'os': 'Unknown',
        'device_type': 'Unknown'
    }
    
    user_agent = user_agent.lower()
    
    # Browser detection
    if 'chrome' in user_agent:
        device_info['browser'] = 'Chrome'
    elif 'firefox' in user_agent:
        device_info['browser'] = 'Firefox'
    elif 'safari' in user_agent and 'chrome' not in user_agent:
        device_info['browser'] = 'Safari'
    elif 'edge' in user_agent:
        device_info['browser'] = 'Edge'
    elif 'opera' in user_agent:
        device_info['browser'] = 'Opera'
    
    # OS detection
    if 'windows' in user_agent:
        device_info['os'] = 'Windows'
    elif 'mac' in user_agent:
        device_info['os'] = 'macOS'
    elif 'linux' in user_agent:
        device_info['os'] = 'Linux'
    elif 'android' in user_agent:
        device_info['os'] = 'Android'
    elif 'iphone' in user_agent or 'ipad' in user_agent:
        device_info['os'] = 'iOS'
    
    # Device type detection
    if 'mobile' in user_agent or 'android' in user_agent or 'iphone' in user_agent:
        device_info['device_type'] = 'Mobile'
    elif 'tablet' in user_agent or 'ipad' in user_agent:
        device_info['device_type'] = 'Tablet'
    else:
        device_info['device_type'] = 'Desktop'
    
    return device_info

def is_suspicious_activity(
    user_id: int,
    ip_address: str,
    device_info: Dict[str, str],
    previous_sessions: list
) -> Dict[str, Any]:
    """Detect suspicious login activity"""
    
    suspicion_score = 0
    flags = []
    
    if not previous_sessions:
        return {"is_suspicious": False, "score": 0, "flags": []}
    
    # Check for new IP address
    previous_ips = [session.get('ip_address') for session in previous_sessions]
    if ip_address not in previous_ips:
        suspicion_score += 30
        flags.append("new_ip_address")
    
    # Check for new device/browser
    previous_devices = [session.get('device_info', {}) for session in previous_sessions]
    current_browser = device_info.get('browser')
    current_os = device_info.get('os')
    
    browser_seen = any(
        device.get('browser') == current_browser 
        for device in previous_devices
    )
    os_seen = any(
        device.get('os') == current_os 
        for device in previous_devices
    )
    
    if not browser_seen:
        suspicion_score += 20
        flags.append("new_browser")
    
    if not os_seen:
        suspicion_score += 25
        flags.append("new_operating_system")
    
    # Check for rapid successive logins
    recent_sessions = [
        session for session in previous_sessions
        if session.get('created_at') and 
        (datetime.utcnow() - session['created_at']).total_seconds() < 300  # 5 minutes
    ]
    
    if len(recent_sessions) > 3:
        suspicion_score += 40
        flags.append("rapid_successive_logins")
    
    # Check for geographically distant IPs (simplified)
    # In production, use proper IP geolocation service
    if len(set(previous_ips[-5:])) > 3:  # More than 3 different IPs in last 5 sessions
        suspicion_score += 35
        flags.append("multiple_locations")
    
    return {
        "is_suspicious": suspicion_score >= 50,
        "score": suspicion_score,
        "flags": flags
    }

def send_email_notification(
    to_email: str,
    subject: str,
    body: str,
    is_html: bool = False
) -> bool:
    """Send email notification"""
    
    try:
        msg = MIMEMultipart()
        msg['From'] = settings.smtp_from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        
        if is_html:
            msg.attach(MIMEText(body, 'html'))
        else:
            msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(settings.smtp_server, settings.smtp_port)
        
        if settings.smtp_use_tls:
            server.starttls()
        
        if settings.smtp_username and settings.smtp_password:
            server.login(settings.smtp_username, settings.smtp_password)
        
        server.send_message(msg)
        server.quit()
        
        logger.info(f"Email sent successfully to {to_email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        return False

def generate_login_notification_email(
    user_name: str,
    login_time: datetime,
    ip_address: str,
    device_info: Dict[str, str],
    is_suspicious: bool = False
) -> str:
    """Generate login notification email HTML"""
    
    status_color = "#dc3545" if is_suspicious else "#28a745"
    status_text = "Suspicious Login Detected" if is_suspicious else "Successful Login"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Login Notification - SatyaLens</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px;">
                <h2 style="color: {status_color}; margin: 0;">{status_text}</h2>
            </div>
            
            <p>Hello {user_name},</p>
            
            <p>We detected a login to your SatyaLens account:</p>
            
            <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <p><strong>Time:</strong> {login_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p><strong>IP Address:</strong> {ip_address}</p>
                <p><strong>Browser:</strong> {device_info.get('browser', 'Unknown')}</p>
                <p><strong>Operating System:</strong> {device_info.get('os', 'Unknown')}</p>
                <p><strong>Device Type:</strong> {device_info.get('device_type', 'Unknown')}</p>
            </div>
            
            {"<p style='color: #dc3545;'><strong>If this wasn't you, please secure your account immediately by changing your password and reviewing your account activity.</strong></p>" if is_suspicious else "<p>If this was you, no action is needed.</p>"}
            
            <p>Best regards,<br>The SatyaLens Team</p>
            
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
            <p style="font-size: 12px; color: #666;">
                This is an automated message. Please do not reply to this email.
            </p>
        </div>
    </body>
    </html>
    """
    
    return html

def sanitize_input(input_string: str, max_length: int = 1000) -> str:
    """Sanitize user input to prevent injection attacks"""
    
    if not input_string:
        return ""
    
    # Remove null bytes
    sanitized = input_string.replace('\x00', '')
    
    # Limit length
    sanitized = sanitized[:max_length]
    
    # Remove potentially dangerous characters for SQL injection
    dangerous_chars = ['<', '>', '"', "'", '&', '\n', '\r', '\t']
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized.strip()

def validate_otp_format(otp: str) -> bool:
    """Validate OTP format"""
    
    return bool(re.match(r'^\d{6}$', otp))

def calculate_password_strength(password: str) -> Dict[str, Any]:
    """Calculate password strength score"""
    
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 8:
        score += 25
    else:
        feedback.append("Password should be at least 8 characters long")
    
    # Uppercase check
    if re.search(r'[A-Z]', password):
        score += 25
    else:
        feedback.append("Add uppercase letters")
    
    # Lowercase check
    if re.search(r'[a-z]', password):
        score += 25
    else:
        feedback.append("Add lowercase letters")
    
    # Number check
    if re.search(r'\d', password):
        score += 15
    else:
        feedback.append("Add numbers")
    
    # Special character check
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 10
    else:
        feedback.append("Add special characters")
    
    # Determine strength level
    if score >= 85:
        strength = "Very Strong"
    elif score >= 70:
        strength = "Strong"
    elif score >= 50:
        strength = "Medium"
    elif score >= 25:
        strength = "Weak"
    else:
        strength = "Very Weak"
    
    return {
        "score": score,
        "strength": strength,
        "feedback": feedback
    }

def format_time_ago(timestamp: datetime) -> str:
    """Format timestamp as 'time ago' string"""
    
    now = datetime.utcnow()
    diff = now - timestamp
    
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return "Just now"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    elif seconds < 2592000:  # 30 days
        days = int(seconds // 86400)
        return f"{days} day{'s' if days != 1 else ''} ago"
    else:
        return timestamp.strftime('%Y-%m-%d')



 