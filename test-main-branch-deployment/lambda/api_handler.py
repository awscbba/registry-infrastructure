import json
import boto3
import uuid
import os
import bcrypt  # Re-enabled with Linux-compatible version
from datetime import datetime, timedelta
from decimal import Decimal
import secrets
import string

# Import email service
from email_service import (
    send_welcome_email,
    send_password_reset_email, 
    send_password_changed_email,
    email_service
)

# Enhanced password service V2 - robust implementation
try:
    from enhanced_password_service_v2 import (
        validate_password_strength_v2,
        change_password_with_history_v2,
        generate_secure_tokens_v2,
        invalidate_all_sessions_v2,
        refresh_token_v2,
        get_active_sessions_v2,
        enhanced_password_service_v2,
        SERVICE_AVAILABLE
    )
    print("Enhanced Password Service V2 imported successfully")
    
    # Use V2 functions
    validate_password_strength = validate_password_strength_v2
    change_password_with_history = change_password_with_history_v2
    generate_secure_tokens = generate_secure_tokens_v2
    invalidate_all_sessions = invalidate_all_sessions_v2
    refresh_token = refresh_token_v2
    get_active_sessions = get_active_sessions_v2
    
    # Define error codes locally to avoid import issues
    PASSWORD_ERROR_CODES = {
        'TOO_SHORT': 'Password must be at least 8 characters',
        'MISSING_UPPERCASE': 'Password must contain uppercase letter',
        'MISSING_LOWERCASE': 'Password must contain lowercase letter',
        'MISSING_NUMBER': 'Password must contain a number',
        'MISSING_SPECIAL': 'Password must contain special character',
        'PASSWORDS_DONT_MATCH': 'Passwords do not match',
        'CURRENT_INCORRECT': 'Current password is incorrect',
        'REUSED_PASSWORD': 'Cannot reuse recent passwords',
        'SAME_AS_CURRENT': 'New password must be different'
    }
    
    SECURITY_ERROR_CODES = {
        'ACCOUNT_LOCKED': 'Account temporarily locked due to failed attempts',
        'INVALID_RESET_TOKEN': 'Password reset link is invalid or expired',
        'TOKEN_EXPIRED': 'Password reset link has expired',
        'TOKEN_ALREADY_USED': 'Password reset link has already been used',
        'SESSION_EXPIRED': 'Session has expired',
        'INVALID_SESSION': 'Invalid session token'
    }
    
except Exception as e:
    print(f"Enhanced Password Service V2 import failed: {str(e)}")
    SERVICE_AVAILABLE = False
    
    # Define error codes for fallback
    PASSWORD_ERROR_CODES = {
        'TOO_SHORT': 'Password must be at least 8 characters',
        'MISSING_UPPERCASE': 'Password must contain uppercase letter',
        'MISSING_LOWERCASE': 'Password must contain lowercase letter',
        'MISSING_NUMBER': 'Password must contain a number',
        'MISSING_SPECIAL': 'Password must contain special character',
        'PASSWORDS_DONT_MATCH': 'Passwords do not match',
        'CURRENT_INCORRECT': 'Current password is incorrect',
        'REUSED_PASSWORD': 'Cannot reuse recent passwords',
        'SAME_AS_CURRENT': 'New password must be different'
    }
    
    SECURITY_ERROR_CODES = {
        'ACCOUNT_LOCKED': 'Account temporarily locked due to failed attempts',
        'INVALID_RESET_TOKEN': 'Password reset link is invalid or expired',
        'TOKEN_EXPIRED': 'Password reset link has expired',
        'TOKEN_ALREADY_USED': 'Password reset link has already been used',
        'SESSION_EXPIRED': 'Session has expired',
        'INVALID_SESSION': 'Invalid session token'
    }
    
    # Fallback functions for basic functionality
    def validate_password_strength(password, confirm_password=None):
        """Basic password validation - fallback implementation"""
        errors = []
        if len(password) < 8:
            errors.append({'field': 'password', 'code': 'TOO_SHORT', 'message': 'Password must be at least 8 characters'})
        if not any(c.isupper() for c in password):
            errors.append({'field': 'password', 'code': 'MISSING_UPPERCASE', 'message': 'Password must contain uppercase letter'})
        if not any(c.islower() for c in password):
            errors.append({'field': 'password', 'code': 'MISSING_LOWERCASE', 'message': 'Password must contain lowercase letter'})
        if not any(c.isdigit() for c in password):
            errors.append({'field': 'password', 'code': 'MISSING_NUMBER', 'message': 'Password must contain a number'})
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append({'field': 'password', 'code': 'MISSING_SPECIAL', 'message': 'Password must contain special character'})
        if confirm_password and password != confirm_password:
            errors.append({'field': 'confirmPassword', 'code': 'PASSWORDS_DONT_MATCH', 'message': 'Passwords do not match'})
        return errors

    def change_password_with_history(*args, **kwargs):
        return {'success': False, 'error': 'Enhanced service temporarily unavailable'}

    def generate_secure_tokens(user_data, device_info=None, ip_address=None, user_agent=None):
        """Generate basic tokens - fallback implementation"""
        import base64
        token_payload = {
            'user_id': user_data['id'],
            'email': user_data['email'],
            'first_name': user_data.get('firstName', ''),
            'last_name': user_data.get('lastName', ''),
            'exp': (datetime.utcnow() + timedelta(hours=24)).timestamp(),
            'iat': datetime.utcnow().timestamp()
        }
        token = base64.b64encode(json.dumps(token_payload).encode()).decode()
        return {
            'accessToken': token,
            'refreshToken': token,
            'expiresAt': (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            'refreshExpiresAt': (datetime.utcnow() + timedelta(days=7)).isoformat()
        }

    def invalidate_all_sessions(*args, **kwargs):
        return 0

    def refresh_token(*args, **kwargs):
        return None

    def get_active_sessions(*args, **kwargs):
        return []

dynamodb = boto3.resource('dynamodb')
ses_client = boto3.client('ses')

# Custom JSON encoder to handle Decimal objects from DynamoDB
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            # Convert decimal to int if it's a whole number, otherwise to float
            if obj % 1 == 0:
                return int(obj)
            else:
                return float(obj)
        return super(DecimalEncoder, self).default(obj)

# Password utility functions
def hash_password(password):
    """Hash a password using bcrypt with salt"""
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
    return {
        'hash': password_hash.decode('utf-8'),
        'salt': salt.decode('utf-8')
    }

def validate_password_strength(password):
    """Validate password meets security requirements"""
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")
    
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        errors.append("Password must contain at least one special character")
    
    return {
        'valid': len(errors) == 0,
        'errors': errors
    }

def verify_password(password, stored_hash):
    """Verify a password against stored hash"""
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

def validate_password_policy(password):
    """Validate password meets security requirements"""
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")
    
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if not any(c in special_chars for c in password):
        errors.append("Password must contain at least one special character")
    
    return errors

def create_security_event_log(audit_logs_table, event_type, person_id=None, success=True, details=None, ip_address=None, user_agent=None, severity='INFO'):
    """Create a security-focused audit log entry"""
    try:
        log_entry = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'eventType': event_type,
            'success': success,
            'severity': severity,  # INFO, WARNING, CRITICAL
            'ipAddress': ip_address or 'unknown',
            'userAgent': user_agent or 'unknown',
            'details': details or {}
        }
        
        if person_id:
            log_entry['personId'] = person_id
        
        # Add additional security context
        log_entry['details']['timestamp_readable'] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        log_entry['details']['event_category'] = get_event_category(event_type)
        
        audit_logs_table.put_item(Item=log_entry)
        
        # Log to CloudWatch for monitoring
        print(f"SECURITY_EVENT: {event_type} | Success: {success} | Severity: {severity} | Person: {person_id} | IP: {ip_address}")
        
        return True
        
    except Exception as e:
        print(f"Error creating security event log: {str(e)}")
        return False

def get_event_category(event_type):
    """Categorize security events for better monitoring"""
    authentication_events = [
        'LOGIN_SUCCESS', 'LOGIN_FAILED', 'LOGOUT', 'SESSION_EXPIRED',
        'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'MULTIPLE_FAILED_ATTEMPTS'
    ]
    
    password_events = [
        'PASSWORD_CHANGED', 'PASSWORD_RESET_REQUESTED', 'PASSWORD_RESET_COMPLETED',
        'FIRST_TIME_PASSWORD_CHANGE', 'ADMIN_PASSWORD_RESET', 'PASSWORD_POLICY_VIOLATION'
    ]
    
    admin_events = [
        'ADMIN_LOGIN', 'ADMIN_ACTION', 'ADMIN_PASSWORD_RESET_TEMPORARY',
        'ADMIN_PASSWORD_RESET_EMAIL', 'ADMIN_ACCOUNT_UNLOCK'
    ]
    
    suspicious_events = [
        'BRUTE_FORCE_ATTEMPT', 'SUSPICIOUS_LOGIN_PATTERN', 'RAPID_PASSWORD_CHANGES',
        'INVALID_TOKEN_USAGE', 'ACCOUNT_ENUMERATION_ATTEMPT'
    ]
    
    if event_type in authentication_events:
        return 'AUTHENTICATION'
    elif event_type in password_events:
        return 'PASSWORD_MANAGEMENT'
    elif event_type in admin_events:
        return 'ADMIN_ACTION'
    elif event_type in suspicious_events:
        return 'SECURITY_ALERT'
    else:
        return 'GENERAL'

def log_authentication_event(audit_logs_table, event_type, person_id, success, email=None, ip_address=None, user_agent=None, additional_details=None):
    """Log authentication-specific events with enhanced details"""
    details = {
        'email': email or 'unknown',
        'authentication_method': 'password',
        'session_info': {
            'created_at': datetime.utcnow().isoformat(),
            'ip_address': ip_address,
            'user_agent': user_agent
        }
    }
    
    if additional_details:
        details.update(additional_details)
    
    severity = 'INFO' if success else 'WARNING'
    if event_type in ['ACCOUNT_LOCKED', 'MULTIPLE_FAILED_ATTEMPTS']:
        severity = 'CRITICAL'
    
    return create_security_event_log(
        audit_logs_table=audit_logs_table,
        event_type=event_type,
        person_id=person_id,
        success=success,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        severity=severity
    )

def log_password_event(audit_logs_table, event_type, person_id, success, email=None, ip_address=None, user_agent=None, additional_details=None):
    """Log password management events with enhanced details"""
    details = {
        'email': email or 'unknown',
        'password_policy_enforced': True,
        'security_context': {
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': ip_address,
            'user_agent': user_agent
        }
    }
    
    if additional_details:
        details.update(additional_details)
    
    severity = 'INFO' if success else 'WARNING'
    
    return create_security_event_log(
        audit_logs_table=audit_logs_table,
        event_type=event_type,
        person_id=person_id,
        success=success,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        severity=severity
    )

def log_admin_event(audit_logs_table, event_type, admin_id, target_person_id=None, success=True, ip_address=None, user_agent=None, additional_details=None):
    """Log admin actions with enhanced security tracking"""
    details = {
        'admin_id': admin_id,
        'target_person_id': target_person_id,
        'admin_action_context': {
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': ip_address,
            'user_agent': user_agent,
            'requires_audit': True
        }
    }
    
    if additional_details:
        details.update(additional_details)
    
    return create_security_event_log(
        audit_logs_table=audit_logs_table,
        event_type=event_type,
        person_id=target_person_id,
        success=success,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        severity='INFO'
    )

def get_security_dashboard_data(audit_logs_table, time_range_hours=24):
    """Get security dashboard data for admin monitoring"""
    try:
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)
        
        # Query recent security events
        response = audit_logs_table.scan(
            FilterExpression='#ts BETWEEN :start_time AND :end_time',
            ExpressionAttributeNames={'#ts': 'timestamp'},
            ExpressionAttributeValues={
                ':start_time': start_time.isoformat(),
                ':end_time': end_time.isoformat()
            }
        )
        
        events = response.get('Items', [])
        
        # Analyze events
        dashboard_data = {
            'time_range': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat(),
                'hours': time_range_hours
            },
            'summary': {
                'total_events': len(events),
                'successful_events': len([e for e in events if e.get('success', False)]),
                'failed_events': len([e for e in events if not e.get('success', False)]),
                'critical_events': len([e for e in events if e.get('severity') == 'CRITICAL']),
                'warning_events': len([e for e in events if e.get('severity') == 'WARNING'])
            },
            'event_categories': {},
            'recent_events': sorted(events, key=lambda x: x.get('timestamp', ''), reverse=True)[:20],
            'security_alerts': []
        }
        
        # Categorize events
        for event in events:
            event_type = event.get('eventType', 'UNKNOWN')
            category = get_event_category(event_type)
            
            if category not in dashboard_data['event_categories']:
                dashboard_data['event_categories'][category] = {
                    'total': 0,
                    'successful': 0,
                    'failed': 0,
                    'events': []
                }
            
            dashboard_data['event_categories'][category]['total'] += 1
            if event.get('success', False):
                dashboard_data['event_categories'][category]['successful'] += 1
            else:
                dashboard_data['event_categories'][category]['failed'] += 1
            
            dashboard_data['event_categories'][category]['events'].append(event)
        
        # Identify security alerts
        failed_logins = [e for e in events if e.get('eventType') == 'LOGIN_FAILED']
        if len(failed_logins) > 10:
            dashboard_data['security_alerts'].append({
                'type': 'HIGH_FAILED_LOGIN_RATE',
                'severity': 'WARNING',
                'message': f'{len(failed_logins)} failed login attempts in the last {time_range_hours} hours',
                'count': len(failed_logins)
            })
        
        locked_accounts = [e for e in events if e.get('eventType') == 'ACCOUNT_LOCKED']
        if len(locked_accounts) > 0:
            dashboard_data['security_alerts'].append({
                'type': 'ACCOUNT_LOCKOUTS',
                'severity': 'CRITICAL',
                'message': f'{len(locked_accounts)} account lockouts in the last {time_range_hours} hours',
                'count': len(locked_accounts)
            })
        
        return dashboard_data
        
    except Exception as e:
        print(f"Error getting security dashboard data: {str(e)}")
        return {
            'error': str(e),
            'summary': {'total_events': 0, 'successful_events': 0, 'failed_events': 0}
        }

def create_audit_log(audit_logs_table, person_id, action, success, details=None, ip_address=None, user_agent=None):
    """Create an audit log entry"""
    log_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()
    
    audit_log = {
        'id': log_id,
        'personId': person_id,
        'action': action,
        'timestamp': timestamp,
        'success': success,
        'ipAddress': ip_address or 'unknown',
        'userAgent': user_agent or 'unknown',
        'details': details or {}
    }
    
    audit_logs_table.put_item(Item=audit_log)
    return audit_log

# Password reset utility functions
def generate_reset_token():
    """Generate a secure reset token"""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

def get_token_expiry():
    """Get expiration time for reset tokens (1 hour from now)"""
    return (datetime.utcnow() + timedelta(hours=1)).isoformat()

def is_token_expired(expires_at_str):
    """Check if a token is expired"""
    try:
        expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
        return datetime.utcnow() > expires_at.replace(tzinfo=None)
    except:
        return True

def get_person_by_email(people_table, email):
    """Get person by email address"""
    try:
        response = people_table.scan(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        items = response.get('Items', [])
        return items[0] if items else None
    except Exception as e:
        print(f"Error getting person by email: {str(e)}")
        return None

# Email utility functions
def send_password_reset_email(to_email, first_name, reset_token, admin_initiated=False, admin_name=None):
    """Send password reset email via AWS SES"""
    try:
        frontend_url = os.environ.get('FRONTEND_URL', 'https://d28z2il3z2vmpc.cloudfront.net')
        from_email = os.environ.get('SES_FROM_EMAIL', 'noreply@people-register.local')
        reset_link = f"{frontend_url}/reset-password?token={reset_token}"
        
        # Determine email subject and admin notice
        if admin_initiated:
            email_subject = 'Password Reset (Administrator Initiated) - People Register'
            admin_notice_html = f'<div style="background: #e3f2fd; border: 1px solid #2196f3; padding: 15px; border-radius: 5px; margin: 20px 0;"><strong>🔧 Administrator Action:</strong><br>This password reset was initiated by an administrator ({admin_name or "System Administrator"}).</div>'
            admin_notice_text = f'\n\nADMINISTRATOR ACTION:\nThis password reset was initiated by an administrator ({admin_name or "System Administrator"}).\n'
        else:
            email_subject = 'Reset Your Password - People Register'
            admin_notice_html = ''
            admin_notice_text = ''
        
        # HTML email body
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
                .button {{ display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Password Reset Request</h1>
                </div>
                <div class="content">
                    <h2>Hello {first_name},</h2>
                    <p>We received a request to reset your password for your People Register account.</p>
                    <div style="text-align: center;">
                        <a href="{reset_link}" class="button">Reset My Password</a>
                    </div>
                    <div class="warning">
                        <strong>⚠️ Important:</strong>
                        <ul>
                            <li>This link will expire in 1 hour</li>
                            <li>This link can only be used once</li>
                            <li>If you didn't request this reset, please ignore this email</li>
                        </ul>
                    </div>
                    <p>If the button doesn't work, copy this link: {reset_link}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text email body
        text_body = f"""
        Password Reset Request - People Register
        
        Hello {first_name},
        
        We received a request to reset your password for your People Register account.{admin_notice_text}
        
        To reset your password, please visit this link:
        {reset_link}
        
        IMPORTANT:
        - This link will expire in 1 hour
        - This link can only be used once
        - If you didn't request this reset, please ignore this email
        
        © 2024 People Register. All rights reserved.
        """
        
        # Send email via SES
        response = ses_client.send_email(
            Source=from_email,  # Use just the email address, not the formatted name
            Destination={'ToAddresses': [to_email]},
            Message={
                'Subject': {
                    'Data': email_subject,
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Html': {
                        'Data': html_body,
                        'Charset': 'UTF-8'
                    },
                    'Text': {
                        'Data': text_body,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )
        
        return {
            'success': True,
            'message_id': response.get('MessageId'),
            'message': 'Password reset email sent successfully'
        }
        
    except Exception as e:
        print(f"Error sending password reset email: {str(e)}")
        return {
            'success': False,
            'message': f'Failed to send email: {str(e)}'
        }

def send_password_changed_email(to_email, first_name, change_time, ip_address=None):
    """Send password changed confirmation email via AWS SES"""
    try:
        from_email = os.environ.get('SES_FROM_EMAIL', 'noreply@people-register.local')
        
        # HTML email body
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #00b894 0%, #00a085 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
                .success {{ background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ Password Changed Successfully</h1>
                </div>
                <div class="content">
                    <h2>Hello {first_name},</h2>
                    <div class="success">
                        <strong>✅ Your password has been successfully changed!</strong>
                    </div>
                    <p>This email confirms that your People Register account password was changed on {change_time}.</p>
                    <p><strong>Change Details:</strong></p>
                    <ul>
                        <li>Date & Time: {change_time}</li>
                        <li>IP Address: {ip_address or 'Not available'}</li>
                    </ul>
                    <p>If you did NOT make this change, please contact our support team immediately.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text email body
        text_body = f"""
        Password Changed Successfully - People Register
        
        Hello {first_name},
        
        This email confirms that your People Register account password was changed on {change_time}.
        
        Change Details:
        - Date & Time: {change_time}
        - IP Address: {ip_address or 'Not available'}
        
        If you did NOT make this change, please contact our support team immediately.
        
        © 2024 People Register. All rights reserved.
        """
        
        # Send email via SES
        response = ses_client.send_email(
            Source=from_email,  # Use just the email address, not the formatted name
            Destination={'ToAddresses': [to_email]},
            Message={
                'Subject': {
                    'Data': 'Password Changed - People Register',
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Html': {
                        'Data': html_body,
                        'Charset': 'UTF-8'
                    },
                    'Text': {
                        'Data': text_body,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )
        
        return {
            'success': True,
            'message_id': response.get('MessageId'),
            'message': 'Password changed confirmation email sent successfully'
        }
        
    except Exception as e:
        print(f"Error sending password changed email: {str(e)}")
        return {
            'success': False,
            'message': f'Failed to send email: {str(e)}'
        }

# Authentication and login functions
def login_user(people_table, audit_logs_table, event):
    """Authenticate user and handle first-time login detection"""
    try:
        body = json.loads(event.get('body', '{}'))
        email = body.get('email', '').strip().lower()
        password = body.get('password', '')
        
        if not email or not password:
            return error_response(400, 'Email and password are required')
        
        # Get client information
        client_ip = get_client_ip(event)
        user_agent = get_user_agent(event)
        
        # Check IP-based rate limiting for authentication
        rate_limit_status = check_ip_rate_limit(audit_logs_table, client_ip, 'auth')
        if rate_limit_status.get('blocked'):
            # Log rate limit violation
            log_rate_limit_attempt(audit_logs_table, client_ip, 'login', user_agent)
            
            return {
                'statusCode': 429,
                'headers': {
                    **get_cors_headers(),
                    'Retry-After': str(rate_limit_status.get('retry_after_minutes', 15) * 60)
                },
                'body': json.dumps({
                    'error': 'Too many login attempts',
                    'message': rate_limit_status.get('reason', 'Rate limit exceeded'),
                    'retry_after_minutes': rate_limit_status.get('retry_after_minutes', 15)
                })
            }
        
        # Find person by email
        person = get_person_by_email(people_table, email)
        if not person:
            # Log failed login attempt
            create_audit_log(
                audit_logs_table,
                'unknown',
                'LOGIN_FAILED',
                False,
                {'email': email, 'reason': 'user_not_found'},
                client_ip,
                user_agent
            )
            return error_response(401, 'Invalid email or password')
        
        # Check if account is locked
        if person.get('accountLockedUntil'):
            locked_until = datetime.fromisoformat(person['accountLockedUntil'].replace('Z', '+00:00'))
            if datetime.utcnow() < locked_until.replace(tzinfo=None):
                return error_response(423, 'Account is temporarily locked due to too many failed login attempts')
        
        # Verify password
        stored_hash = person.get('passwordHash')
        if not stored_hash or not verify_password(password, stored_hash):
            # Increment failed login attempts
            failed_attempts = person.get('failedLoginAttempts', 0) + 1
            update_expression = 'SET failedLoginAttempts = :attempts'
            expression_values = {':attempts': failed_attempts}
            
            # Lock account after 5 failed attempts
            if failed_attempts >= 5:
                locked_until = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
                update_expression += ', accountLockedUntil = :locked_until'
                expression_values[':locked_until'] = locked_until
            
            people_table.update_item(
                Key={'id': person['id']},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values
            )
            
            # Log failed login attempt with enhanced security logging
            log_authentication_event(
                audit_logs_table,
                'LOGIN_FAILED',
                person['id'],
                False,
                email=email,
                ip_address=client_ip,
                user_agent=user_agent,
                additional_details={
                    'reason': 'invalid_password',
                    'failed_attempts': failed_attempts,
                    'account_locked': failed_attempts >= 5
                }
            )
            
            # Log account lockout if applicable
            if failed_attempts >= 5:
                log_authentication_event(
                    audit_logs_table,
                    'ACCOUNT_LOCKED',
                    person['id'],
                    True,
                    email=email,
                    ip_address=client_ip,
                    user_agent=user_agent,
                    additional_details={
                        'lockout_duration_minutes': 15,
                        'locked_until': locked_until,
                        'trigger_event': 'multiple_failed_attempts'
                    }
                )
            
            return error_response(401, 'Invalid email or password')
        
        # Successful login - reset failed attempts and update last login
        people_table.update_item(
            Key={'id': person['id']},
            UpdateExpression='SET failedLoginAttempts = :zero, lastLoginAt = :timestamp REMOVE accountLockedUntil',
            ExpressionAttributeValues={
                ':zero': 0,
                ':timestamp': datetime.utcnow().isoformat()
            }
        )
        
        # Check if this is first-time login (requirePasswordChange flag)
        require_password_change = person.get('requirePasswordChange', False)
        
        # Generate secure token pair with session tracking
        device_info = f"{user_agent[:50]}..." if len(user_agent) > 50 else user_agent
        tokens = generate_secure_tokens(
            user_data=person,
            device_info=device_info,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        # Log successful login with enhanced security logging
        log_authentication_event(
            audit_logs_table,
            'LOGIN_SUCCESS',
            person['id'],
            True,
            email=email,
            ip_address=client_ip,
            user_agent=user_agent,
            additional_details={
                'first_time_login': require_password_change,
                'session_duration_hours': 1,  # Access token duration
                'authentication_method': 'password',
                'account_status': 'active',
                'token_type': 'jwt_with_refresh'
            }
        )
        
        # Check for suspicious activity patterns
        suspicious_patterns = detect_suspicious_activity(
            audit_logs_table, 
            person['id'], 
            'LOGIN_SUCCESS', 
            client_ip, 
            user_agent
        )
        
        # Send suspicious activity alerts if patterns detected
        if suspicious_patterns:
            for pattern in suspicious_patterns:
                if pattern['severity'] in ['HIGH', 'CRITICAL']:
                    activity_details = {
                        'type': pattern['type'],
                        'time': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'description': pattern['description']
                    }
                    
                    alert_email_result = send_suspicious_activity_alert_email(
                        person['email'],
                        person.get('firstName', 'User'),
                        activity_details,
                        client_ip
                    )
                    
                    if alert_email_result['success']:
                        print(f"Suspicious activity alert sent to: {person['email']} for {pattern['type']}")
                    else:
                        print(f"Failed to send suspicious activity alert: {alert_email_result['message']}")
                    
                    # Log the security alert
                    log_authentication_event(
                        audit_logs_table,
                        'SUSPICIOUS_ACTIVITY_DETECTED',
                        person['id'],
                        True,
                        email=email,
                        ip_address=client_ip,
                        user_agent=user_agent,
                        additional_details={
                            'pattern_type': pattern['type'],
                            'severity': pattern['severity'],
                            'description': pattern['description'],
                            'alert_sent': alert_email_result['success']
                        }
                    )
        
        # Prepare response with enhanced token structure
        response_data = {
            'success': True,
            'message': 'Login successful',
            'accessToken': tokens['accessToken'],
            'refreshToken': tokens['refreshToken'],
            'expiresAt': tokens['expiresAt'],
            'refreshExpiresAt': tokens['refreshExpiresAt'],
            'user': {
                'id': person['id'],
                'email': person['email'],
                'firstName': person.get('firstName', ''),
                'lastName': person.get('lastName', ''),
                'requirePasswordChange': require_password_change
            }
        }
        
        # Add first-time login flag if applicable
        if require_password_change:
            response_data['requirePasswordChange'] = True
            response_data['message'] = 'Login successful. You must change your password before continuing.'
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps(response_data)
        }
        
    except Exception as e:
        print(f"Error during login: {str(e)}")
        return error_response(500, 'Internal server error')

def logout_user(event):
    """Handle user logout"""
    try:
        # For JWT-based authentication, logout is typically handled client-side
        # by removing the token from storage. Server-side logout would require
        # token blacklisting which we don't implement here for simplicity.
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps({
                'success': True,
                'message': 'Logout successful'
            })
        }
        
    except Exception as e:
        print(f"Logout error: {str(e)}")
        return error_response(500, 'Internal server error during logout')

def get_current_user(people_table, event):
    """Get current user profile from JWT token"""
    try:
        # Extract token from Authorization header
        headers = event.get('headers', {})
        auth_header = headers.get('Authorization') or headers.get('authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return error_response(401, 'Missing or invalid authorization header')
        
        token = auth_header.replace('Bearer ', '')
        
        try:
            # Verify and decode JWT token
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            person_id = payload.get('sub')
            
            if not person_id:
                return error_response(401, 'Invalid token payload')
            
            # Get person from database
            response = people_table.get_item(Key={'id': person_id})
            
            if 'Item' not in response:
                return error_response(404, 'User not found')
            
            person = response['Item']
            
            # Return user profile (excluding sensitive data)
            user_profile = {
                'id': person['id'],
                'email': person['email'],
                'firstName': person.get('firstName', ''),
                'lastName': person.get('lastName', ''),
                'createdAt': person.get('createdAt', ''),
                'updatedAt': person.get('updatedAt', '')
            }
            
            return {
                'statusCode': 200,
                'headers': get_cors_headers(),
                'body': json.dumps({
                    'success': True,
                    'user': user_profile
                })
            }
            
        except jwt.ExpiredSignatureError:
            return error_response(401, 'Token has expired')
        except jwt.InvalidTokenError:
            return error_response(401, 'Invalid token')
        
    except Exception as e:
        print(f"Get current user error: {str(e)}")
        return error_response(500, 'Internal server error')

def change_password_profile(people_table, audit_logs_table, event):
    """Handle password change from user profile - Enhanced with history tracking"""
    try:
        body = json.loads(event.get('body', '{}'))
        current_password = body.get('currentPassword', '')
        new_password = body.get('newPassword', '')
        confirm_password = body.get('confirmPassword', '')
        user_id = body.get('userId', '')
        
        if not all([current_password, new_password, confirm_password, user_id]):
            return error_response(400, 'All password fields and user ID are required')
        
        # Get client information
        client_ip = get_client_ip(event)
        user_agent = get_user_agent(event)
        
        # Use enhanced password service with history checking
        result = change_password_with_history(
            user_id=user_id,
            current_password=current_password,
            new_password=new_password,
            confirm_password=confirm_password,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        if not result['success']:
            if 'errors' in result:
                # Return structured validation errors
                return {
                    'statusCode': 400,
                    'headers': get_cors_headers(),
                    'body': json.dumps({
                        'error': 'Password validation failed',
                        'validation_errors': result['errors']
                    })
                }
            else:
                return error_response(400, result.get('error', 'Password change failed'))
        
        # Get person data for email notification
        try:
            response = people_table.get_item(Key={'id': user_id})
            person = response.get('Item')
            if person:
                # Send password change confirmation email
                email_result = send_password_changed_email(
                    recipient_email=person['email'],
                    first_name=person.get('firstName', 'User'),
                    change_type='Profile Update',
                    ip_address=client_ip,
                    user_agent=user_agent
                )
                
                if email_result['success']:
                    print(f"Password change confirmation email sent to: {person['email']}")
        except Exception as e:
            print(f"Error sending password change email: {str(e)}")
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps({
                'success': True,
                'message': 'Password changed successfully',
                'invalidated_sessions': result.get('invalidated_sessions', 0)
            })
        }
        
    except Exception as e:
        print(f"Error in change_password_profile: {str(e)}")
        return error_response(500, 'Internal server error')


def get_security_dashboard(audit_logs_table, event):
    """Get security dashboard data for admin monitoring"""
    try:
        # Get query parameters
        query_params = event.get('queryStringParameters') or {}
        time_range_hours = int(query_params.get('hours', 24))
        
        # Validate time range
        if time_range_hours < 1 or time_range_hours > 168:  # Max 1 week
            time_range_hours = 24
        
        dashboard_data = get_security_dashboard_data(audit_logs_table, time_range_hours)
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps({
                'success': True,
                'dashboard': dashboard_data
            }, cls=DecimalEncoder)
        }
        
    except Exception as e:
        print(f"Error getting security dashboard: {str(e)}")
        return error_response(500, 'Internal server error')

def get_security_events(audit_logs_table, event):
    """Get filtered security events for monitoring"""
    try:
        query_params = event.get('queryStringParameters') or {}
        
        # Parse filters
        event_type = query_params.get('eventType')
        severity = query_params.get('severity')
        person_id = query_params.get('personId')
        hours = int(query_params.get('hours', 24))
        limit = int(query_params.get('limit', 50))
        
        # Build filter expression
        filter_expressions = []
        expression_values = {}
        expression_names = {}
        
        # Time range filter
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        filter_expressions.append('#ts BETWEEN :start_time AND :end_time')
        expression_names['#ts'] = 'timestamp'
        expression_values[':start_time'] = start_time.isoformat()
        expression_values[':end_time'] = end_time.isoformat()
        
        # Event type filter
        if event_type:
            filter_expressions.append('eventType = :event_type')
            expression_values[':event_type'] = event_type
        
        # Severity filter
        if severity:
            filter_expressions.append('severity = :severity')
            expression_values[':severity'] = severity
        
        # Person ID filter
        if person_id:
            filter_expressions.append('personId = :person_id')
            expression_values[':person_id'] = person_id
        
        # Execute query
        scan_kwargs = {
            'FilterExpression': ' AND '.join(filter_expressions),
            'ExpressionAttributeNames': expression_names,
            'ExpressionAttributeValues': expression_values,
            'Limit': limit
        }
        
        response = audit_logs_table.scan(**scan_kwargs)
        events = response.get('Items', [])
        
        # Sort by timestamp (most recent first)
        events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps({
                'success': True,
                'events': events,
                'count': len(events),
                'filters': {
                    'eventType': event_type,
                    'severity': severity,
                    'personId': person_id,
                    'hours': hours,
                    'limit': limit
                }
            }, cls=DecimalEncoder)
        }
        
    except Exception as e:
        print(f"Error getting security events: {str(e)}")
        return error_response(500, 'Internal server error')

def admin_unlock_account(people_table, audit_logs_table, event):
    """Admin function to unlock a locked user account"""
    try:
        body = json.loads(event.get('body', '{}'))
        person_id = body.get('personId', '').strip()
        admin_id = body.get('adminId', '').strip()
        
        if not person_id or not admin_id:
            return error_response(400, 'Person ID and admin ID are required')
        
        # Get client information
        client_ip = get_client_ip(event)
        user_agent = get_user_agent(event)
        
        # Verify admin exists
        admin = people_table.get_item(Key={'id': admin_id}).get('Item')
        if not admin:
            return error_response(404, 'Admin not found')
        
        # Verify person exists
        person = people_table.get_item(Key={'id': person_id}).get('Item')
        if not person:
            return error_response(404, 'Person not found')
        
        # Check if account is actually locked
        is_locked = False
        locked_until = None
        if person.get('accountLockedUntil'):
            locked_until = datetime.fromisoformat(person['accountLockedUntil'].replace('Z', '+00:00'))
            is_locked = datetime.utcnow() < locked_until.replace(tzinfo=None)
        
        if not is_locked:
            return error_response(400, 'Account is not currently locked')
        
        # Unlock the account
        people_table.update_item(
            Key={'id': person_id},
            UpdateExpression='SET failedLoginAttempts = :zero REMOVE accountLockedUntil',
            ExpressionAttributeValues={':zero': 0}
        )
        
        # Log admin unlock action
        create_audit_log(
            audit_logs_table,
            person_id,
            'ADMIN_ACCOUNT_UNLOCK',
            True,
            {
                'admin_id': admin_id,
                'admin_email': admin.get('email', 'unknown'),
                'person_email': person.get('email', 'unknown'),
                'was_locked_until': person.get('accountLockedUntil'),
                'failed_attempts_reset': person.get('failedLoginAttempts', 0)
            },
            client_ip,
            user_agent
        )
        
        # Send notification email to person
        unlock_notification_result = send_admin_action_notification_email(
            person.get('email', ''),
            person.get('firstName', 'User'),
            admin.get('firstName', 'Administrator'),
            {
                'type': 'Account Unlock',
                'time': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'description': 'Your account has been unlocked by an administrator'
            }
        )
        
        if unlock_notification_result['success']:
            print(f"Account unlock notification sent to: {person.get('email')}")
        else:
            print(f"Failed to send unlock notification: {unlock_notification_result['message']}")
        
        print(f"Admin account unlock completed for person: {person_id} by admin: {admin_id}")
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps({
                'success': True,
                'message': 'Account unlocked successfully',
                'personEmail': person.get('email', ''),
                'personName': f"{person.get('firstName', '')} {person.get('lastName', '')}".strip(),
                'unlockedAt': datetime.utcnow().isoformat()
            })
        }
        
    except Exception as e:
        print(f"Error in admin account unlock: {str(e)}")
        return error_response(500, 'Internal server error')

# IP-based rate limiting functionality
def check_ip_rate_limit(audit_logs_table, client_ip, endpoint_type='auth'):
    """Check if IP address has exceeded rate limits for authentication endpoints"""
    try:
        # Define rate limits per endpoint type
        rate_limits = {
            'auth': {'requests': 10, 'window_minutes': 15},  # 10 auth requests per 15 minutes
            'password_reset': {'requests': 5, 'window_minutes': 60},  # 5 reset requests per hour
            'general': {'requests': 100, 'window_minutes': 15}  # 100 general requests per 15 minutes
        }
        
        limit_config = rate_limits.get(endpoint_type, rate_limits['general'])
        
        # Calculate time window
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=limit_config['window_minutes'])
        
        # Query recent requests from this IP
        response = audit_logs_table.scan(
            FilterExpression='ipAddress = :ip AND #ts BETWEEN :start_time AND :end_time',
            ExpressionAttributeNames={'#ts': 'timestamp'},
            ExpressionAttributeValues={
                ':ip': client_ip,
                ':start_time': start_time.isoformat(),
                ':end_time': end_time.isoformat()
            }
        )
        
        events = response.get('Items', [])
        
        # Filter events by endpoint type
        relevant_events = []
        if endpoint_type == 'auth':
            relevant_events = [e for e in events if e.get('action') in ['LOGIN_SUCCESS', 'LOGIN_FAILED']]
        elif endpoint_type == 'password_reset':
            relevant_events = [e for e in events if 'PASSWORD_RESET' in e.get('action', '')]
        else:
            relevant_events = events
        
        request_count = len(relevant_events)
        
        if request_count >= limit_config['requests']:
            # Log rate limit violation
            create_audit_log(
                audit_logs_table,
                'system',
                'RATE_LIMIT_EXCEEDED',
                False,
                {
                    'ip_address': client_ip,
                    'endpoint_type': endpoint_type,
                    'request_count': request_count,
                    'limit': limit_config['requests'],
                    'window_minutes': limit_config['window_minutes']
                },
                client_ip,
                'system'
            )
            
            return {
                'blocked': True,
                'reason': f'Rate limit exceeded: {request_count}/{limit_config["requests"]} requests in {limit_config["window_minutes"]} minutes',
                'retry_after_minutes': limit_config['window_minutes']
            }
        
        return {
            'blocked': False,
            'remaining_requests': limit_config['requests'] - request_count,
            'window_minutes': limit_config['window_minutes']
        }
        
    except Exception as e:
        print(f"Error checking IP rate limit: {str(e)}")
        # In case of error, allow the request but log the issue
        return {'blocked': False, 'error': str(e)}

def log_rate_limit_attempt(audit_logs_table, client_ip, endpoint, user_agent):
    """Log rate limit attempts for monitoring"""
    try:
        create_audit_log(
            audit_logs_table,
            'system',
            'RATE_LIMIT_CHECK',
            True,
            {
                'endpoint': endpoint,
                'ip_address': client_ip,
                'user_agent': user_agent,
                'timestamp': datetime.utcnow().isoformat()
            },
            client_ip,
            user_agent
        )
    except Exception as e:
        print(f"Error logging rate limit attempt: {str(e)}")

def get_account_lockout_status(people_table, person_id):
    """Get detailed account lockout status for admin dashboard"""
    try:
        person = people_table.get_item(Key={'id': person_id}).get('Item')
        if not person:
            return {'error': 'Person not found'}
        
        failed_attempts = person.get('failedLoginAttempts', 0)
        locked_until = person.get('accountLockedUntil')
        
        status = {
            'person_id': person_id,
            'email': person.get('email', ''),
            'name': f"{person.get('firstName', '')} {person.get('lastName', '')}".strip(),
            'failed_attempts': failed_attempts,
            'is_locked': False,
            'locked_until': None,
            'remaining_lockout_minutes': 0
        }
        
        if locked_until:
            locked_until_dt = datetime.fromisoformat(locked_until.replace('Z', '+00:00'))
            current_time = datetime.utcnow()
            
            if current_time < locked_until_dt.replace(tzinfo=None):
                status['is_locked'] = True
                status['locked_until'] = locked_until
                remaining_seconds = (locked_until_dt.replace(tzinfo=None) - current_time).total_seconds()
                status['remaining_lockout_minutes'] = max(0, int(remaining_seconds / 60))
        
        return status
        
    except Exception as e:
        print(f"Error getting account lockout status: {str(e)}")
        return {'error': str(e)}

def get_ip_rate_limit_status(audit_logs_table, client_ip):
    """Get current rate limit status for an IP address"""
    try:
        auth_status = check_ip_rate_limit(audit_logs_table, client_ip, 'auth')
        reset_status = check_ip_rate_limit(audit_logs_table, client_ip, 'password_reset')
        general_status = check_ip_rate_limit(audit_logs_table, client_ip, 'general')
        
        return {
            'ip_address': client_ip,
            'auth_requests': auth_status,
            'password_reset_requests': reset_status,
            'general_requests': general_status,
            'timestamp': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        print(f"Error getting IP rate limit status: {str(e)}")
        return {'error': str(e)}

def admin_reset_password(people_table, password_reset_tokens_table, audit_logs_table, event):
    """Admin-initiated password reset"""
    try:
        body = json.loads(event.get('body', '{}'))
        person_id = body.get('personId', '').strip()
        reset_type = body.get('resetType', '')  # 'temporary' or 'email'
        admin_id = body.get('adminId', '').strip()
        
        if not person_id or not reset_type or not admin_id:
            return error_response(400, 'Person ID, reset type, and admin ID are required')
        
        if reset_type not in ['temporary', 'email']:
            return error_response(400, 'Reset type must be either "temporary" or "email"')
        
        # Get client information
        client_ip = get_client_ip(event)
        user_agent = get_user_agent(event)
        
        # Get person record
        try:
            response = people_table.get_item(Key={'id': person_id})
            person = response.get('Item')
            if not person:
                return error_response(404, 'Person not found')
        except Exception as e:
            print(f"Error getting person: {str(e)}")
            return error_response(500, 'Error retrieving person information')
        
        # Get admin record for audit
        try:
            admin_response = people_table.get_item(Key={'id': admin_id})
            admin = admin_response.get('Item')
            if not admin:
                return error_response(404, 'Admin not found')
        except Exception as e:
            print(f"Error getting admin: {str(e)}")
            return error_response(500, 'Error retrieving admin information')
        
        if reset_type == 'temporary':
            # Generate temporary password
            temp_password = generate_temporary_password()
            
            # Hash the temporary password
            password_data = hash_password(temp_password)
            
            # Get current password history
            password_history = person.get('passwordHistory', [])
            
            # Add current password to history if it exists
            if person.get('passwordHash'):
                password_history.append({
                    'passwordHash': person['passwordHash'],
                    'changedAt': datetime.utcnow().isoformat()
                })
                # Keep only last 5 passwords
                password_history = password_history[-5:]
            
            # Update person's password and mark for mandatory change
            people_table.update_item(
                Key={'id': person_id},
                UpdateExpression='SET passwordHash = :hash, passwordSalt = :salt, requirePasswordChange = :require, lastPasswordChange = :timestamp, passwordHistory = :history',
                ExpressionAttributeValues={
                    ':hash': password_data['hash'],
                    ':salt': password_data['salt'],
                    ':require': True,
                    ':timestamp': datetime.utcnow().isoformat(),
                    ':history': password_history
                }
            )
            
            # Log admin action
            create_audit_log(
                audit_logs_table,
                person_id,
                'ADMIN_PASSWORD_RESET_TEMPORARY',
                True,
                {
                    'admin_id': admin_id,
                    'admin_email': admin.get('email', 'unknown'),
                    'person_email': person.get('email', 'unknown'),
                    'reset_type': 'temporary'
                },
                client_ip,
                user_agent
            )
            
            # Send notification email to person
            email_result = send_admin_password_reset_email(
                person.get('email', ''),
                person.get('firstName', 'User'),
                admin.get('firstName', 'Administrator'),
                'temporary'
            )
            
            # Send admin action notification
            admin_action_details = {
                'type': 'Password Reset (Temporary)',
                'time': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'description': 'A temporary password was generated for your account by an administrator'
            }
            
            admin_notification_result = send_admin_action_notification_email(
                person.get('email', ''),
                person.get('firstName', 'User'),
                admin.get('firstName', 'Administrator'),
                admin_action_details
            )
            
            if email_result['success']:
                print(f"Admin password reset notification sent to: {person.get('email')}")
            else:
                print(f"Failed to send admin password reset notification: {email_result['message']}")
                
            if admin_notification_result['success']:
                print(f"Admin action notification sent to: {person.get('email')}")
            else:
                print(f"Failed to send admin action notification: {admin_notification_result['message']}")
            
            print(f"Admin temporary password reset completed for person: {person_id} by admin: {admin_id}")
            
            return {
                'statusCode': 200,
                'headers': get_cors_headers(),
                'body': json.dumps({
                    'success': True,
                    'message': 'Temporary password has been generated successfully.',
                    'temporaryPassword': temp_password,
                    'resetType': 'temporary',
                    'personEmail': person.get('email', ''),
                    'personName': f"{person.get('firstName', '')} {person.get('lastName', '')}".strip()
                })
            }
            
        elif reset_type == 'email':
            # Generate reset token for email-based reset
            reset_token = generate_reset_token()
            expires_at = get_token_expiry()
            
            # Store reset token
            token_record = {
                'resetToken': reset_token,
                'personId': person_id,
                'email': person.get('email', ''),
                'expiresAt': expires_at,
                'isUsed': False,
                'createdAt': datetime.utcnow().isoformat(),
                'ipAddress': client_ip,
                'userAgent': user_agent,
                'initiatedBy': 'admin',
                'adminId': admin_id
            }
            
            password_reset_tokens_table.put_item(Item=token_record)
            
            # Log admin action
            create_audit_log(
                audit_logs_table,
                person_id,
                'ADMIN_PASSWORD_RESET_EMAIL',
                True,
                {
                    'admin_id': admin_id,
                    'admin_email': admin.get('email', 'unknown'),
                    'person_email': person.get('email', 'unknown'),
                    'reset_type': 'email'
                },
                client_ip,
                user_agent
            )
            
            # Send password reset email
            email_result = send_password_reset_email(
                person.get('email', ''),
                person.get('firstName', 'User'),
                reset_token,
                admin_initiated=True,
                admin_name=admin.get('firstName', 'Administrator')
            )
            
            # Send admin action notification
            admin_action_details = {
                'type': 'Password Reset (Email Link)',
                'time': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'description': 'A password reset link was sent to your email by an administrator'
            }
            
            admin_notification_result = send_admin_action_notification_email(
                person.get('email', ''),
                person.get('firstName', 'User'),
                admin.get('firstName', 'Administrator'),
                admin_action_details
            )
            
            if email_result['success']:
                print(f"Admin-initiated password reset email sent to: {person.get('email')}")
            else:
                print(f"Failed to send admin-initiated password reset email: {email_result['message']}")
                
            if admin_notification_result['success']:
                print(f"Admin action notification sent to: {person.get('email')}")
            else:
                print(f"Failed to send admin action notification: {admin_notification_result['message']}")
            
            print(f"Admin email password reset initiated for person: {person_id} by admin: {admin_id}")
            
            return {
                'statusCode': 200,
                'headers': get_cors_headers(),
                'body': json.dumps({
                    'success': True,
                    'message': 'Password reset email has been sent successfully.',
                    'resetType': 'email',
                    'personEmail': person.get('email', ''),
                    'personName': f"{person.get('firstName', '')} {person.get('lastName', '')}".strip()
                })
            }
        
    except Exception as e:
        print(f"Error in admin password reset: {str(e)}")
        return error_response(500, 'Internal server error')

def generate_temporary_password():
    """Generate a secure temporary password"""
    import secrets
    import string
    
    # Define character sets
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special_chars = "!@#$%^&*"
    
    # Ensure at least one character from each required set
    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special_chars)
    ]
    
    # Fill the rest with random characters from all sets
    all_chars = uppercase + lowercase + digits + special_chars
    for _ in range(8):  # Total length will be 12
        password.append(secrets.choice(all_chars))
    
    # Shuffle the password list
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

def send_password_reset_completion_email(to_email, first_name, completion_time, ip_address=None):
    """Send password reset completion confirmation email"""
    try:
        from_email = os.environ.get('SES_FROM_EMAIL', 'noreply@people-register.local')
        
        # HTML email body
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
                .success-box {{ background: #d1fae5; border: 1px solid #10b981; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .security-info {{ background: #fef3c7; border: 1px solid #f59e0b; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Password Reset Completed</h1>
                </div>
                <div class="content">
                    <h2>Hello {first_name},</h2>
                    <div class="success-box">
                        <strong>✅ Your password reset has been completed successfully!</strong>
                    </div>
                    <p>This email confirms that your People Register account password was successfully reset on {completion_time}.</p>
                    <p><strong>Reset Details:</strong></p>
                    <ul>
                        <li>Completion Time: {completion_time}</li>
                        <li>IP Address: {ip_address or 'Not available'}</li>
                        <li>All existing sessions have been invalidated</li>
                        <li>You can now log in with your new password</li>
                    </ul>
                    <div class="security-info">
                        <strong>🛡️ Security Notice:</strong>
                        <p>If you did not initiate this password reset, please contact support immediately and consider the following:</p>
                        <ul>
                            <li>Change your password again immediately</li>
                            <li>Review your account for any unauthorized changes</li>
                            <li>Enable additional security measures if available</li>
                        </ul>
                    </div>
                    <p>Thank you for keeping your account secure!</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text email body
        text_body = f"""
        Password Reset Completed - People Register
        
        Hello {first_name},
        
        Your password reset has been completed successfully!
        
        This email confirms that your People Register account password was successfully reset on {completion_time}.
        
        Reset Details:
        - Completion Time: {completion_time}
        - IP Address: {ip_address or 'Not available'}
        - All existing sessions have been invalidated
        - You can now log in with your new password
        
        SECURITY NOTICE:
        If you did not initiate this password reset, please contact support immediately and consider:
        - Change your password again immediately
        - Review your account for any unauthorized changes
        - Enable additional security measures if available
        
        Thank you for keeping your account secure!
        
        © 2024 People Register. All rights reserved.
        """
        
        # Send email via SES
        response = ses_client.send_email(
            Source=from_email,
            Destination={'ToAddresses': [to_email]},
            Message={
                'Subject': {
                    'Data': 'Password Reset Completed - People Register',
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Html': {
                        'Data': html_body,
                        'Charset': 'UTF-8'
                    },
                    'Text': {
                        'Data': text_body,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )
        
        return {
            'success': True,
            'message_id': response.get('MessageId'),
            'message': 'Password reset completion email sent successfully'
        }
        
    except Exception as e:
        print(f"Error sending password reset completion email: {str(e)}")
        return {
            'success': False,
            'message': f'Failed to send email: {str(e)}'
        }

def send_suspicious_activity_alert_email(to_email, first_name, activity_details, ip_address=None):
    """Send suspicious activity alert email"""
    try:
        from_email = os.environ.get('SES_FROM_EMAIL', 'noreply@people-register.local')
        
        activity_type = activity_details.get('type', 'Unknown')
        activity_time = activity_details.get('time', 'Unknown')
        activity_description = activity_details.get('description', 'Suspicious activity detected')
        
        # HTML email body
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
                .alert-box {{ background: #fee2e2; border: 1px solid #dc2626; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .action-box {{ background: #dbeafe; border: 1px solid #3b82f6; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 Security Alert</h1>
                </div>
                <div class="content">
                    <h2>Hello {first_name},</h2>
                    <div class="alert-box">
                        <strong>⚠️ Suspicious activity detected on your account!</strong>
                    </div>
                    <p>We detected unusual activity on your People Register account that requires your attention.</p>
                    <p><strong>Activity Details:</strong></p>
                    <ul>
                        <li>Activity Type: {activity_type}</li>
                        <li>Time: {activity_time}</li>
                        <li>Description: {activity_description}</li>
                        <li>IP Address: {ip_address or 'Not available'}</li>
                    </ul>
                    <div class="action-box">
                        <strong>🔒 Recommended Actions:</strong>
                        <ul>
                            <li>Change your password immediately if you don't recognize this activity</li>
                            <li>Review your recent account activity</li>
                            <li>Check for any unauthorized changes to your profile</li>
                            <li>Contact support if you need assistance</li>
                        </ul>
                    </div>
                    <p>If this activity was authorized by you, no further action is needed. However, we recommend reviewing your account security settings regularly.</p>
                    <p><strong>Need Help?</strong> Contact our support team if you have any concerns about your account security.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text email body
        text_body = f"""
        SECURITY ALERT - People Register
        
        Hello {first_name},
        
        SUSPICIOUS ACTIVITY DETECTED ON YOUR ACCOUNT!
        
        We detected unusual activity on your People Register account that requires your attention.
        
        Activity Details:
        - Activity Type: {activity_type}
        - Time: {activity_time}
        - Description: {activity_description}
        - IP Address: {ip_address or 'Not available'}
        
        RECOMMENDED ACTIONS:
        - Change your password immediately if you don't recognize this activity
        - Review your recent account activity
        - Check for any unauthorized changes to your profile
        - Contact support if you need assistance
        
        If this activity was authorized by you, no further action is needed. However, we recommend reviewing your account security settings regularly.
        
        Need Help? Contact our support team if you have any concerns about your account security.
        
        © 2024 People Register Security Team. All rights reserved.
        """
        
        # Send email via SES
        response = ses_client.send_email(
            Source=from_email,
            Destination={'ToAddresses': [to_email]},
            Message={
                'Subject': {
                    'Data': '🚨 SECURITY ALERT - Suspicious Activity Detected',
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Html': {
                        'Data': html_body,
                        'Charset': 'UTF-8'
                    },
                    'Text': {
                        'Data': text_body,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )
        
        return {
            'success': True,
            'message_id': response.get('MessageId'),
            'message': 'Suspicious activity alert email sent successfully'
        }
        
    except Exception as e:
        print(f"Error sending suspicious activity alert email: {str(e)}")
        return {
            'success': False,
            'message': f'Failed to send email: {str(e)}'
        }

def send_admin_action_notification_email(to_email, first_name, admin_name, action_details):
    """Send notification email for admin actions"""
    try:
        from_email = os.environ.get('SES_FROM_EMAIL', 'noreply@people-register.local')
        
        action_type = action_details.get('type', 'Administrative Action')
        action_time = action_details.get('time', 'Unknown')
        action_description = action_details.get('description', 'An administrative action was performed on your account')
        
        # HTML email body
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #7c3aed 0%, #5b21b6 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
                .admin-box {{ background: #ede9fe; border: 1px solid #7c3aed; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .info-box {{ background: #e0f2fe; border: 1px solid #0891b2; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔧 Administrative Action Notice</h1>
                </div>
                <div class="content">
                    <h2>Hello {first_name},</h2>
                    <div class="admin-box">
                        <strong>👨‍💼 An administrator has performed an action on your account</strong>
                    </div>
                    <p>This email is to notify you that an administrative action was performed on your People Register account.</p>
                    <p><strong>Action Details:</strong></p>
                    <ul>
                        <li>Action Type: {action_type}</li>
                        <li>Performed By: {admin_name}</li>
                        <li>Time: {action_time}</li>
                        <li>Description: {action_description}</li>
                    </ul>
                    <div class="info-box">
                        <strong>ℹ️ What This Means:</strong>
                        <p>Administrative actions are performed by authorized system administrators to help manage your account or resolve issues. This notification is sent for transparency and security purposes.</p>
                    </div>
                    <p>If you have questions about this action or did not request administrative assistance, please contact support for clarification.</p>
                    <p><strong>Need Help?</strong> Our support team is available to answer any questions about administrative actions on your account.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text email body
        text_body = f"""
        Administrative Action Notice - People Register
        
        Hello {first_name},
        
        An administrator has performed an action on your account.
        
        This email is to notify you that an administrative action was performed on your People Register account.
        
        Action Details:
        - Action Type: {action_type}
        - Performed By: {admin_name}
        - Time: {action_time}
        - Description: {action_description}
        
        WHAT THIS MEANS:
        Administrative actions are performed by authorized system administrators to help manage your account or resolve issues. This notification is sent for transparency and security purposes.
        
        If you have questions about this action or did not request administrative assistance, please contact support for clarification.
        
        Need Help? Our support team is available to answer any questions about administrative actions on your account.
        
        © 2024 People Register. All rights reserved.
        """
        
        # Send email via SES
        response = ses_client.send_email(
            Source=from_email,
            Destination={'ToAddresses': [to_email]},
            Message={
                'Subject': {
                    'Data': f'Administrative Action Notice - {action_type}',
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Html': {
                        'Data': html_body,
                        'Charset': 'UTF-8'
                    },
                    'Text': {
                        'Data': text_body,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )
        
        return {
            'success': True,
            'message_id': response.get('MessageId'),
            'message': 'Admin action notification email sent successfully'
        }
        
    except Exception as e:
        print(f"Error sending admin action notification email: {str(e)}")
        return {
            'success': False,
            'message': f'Failed to send email: {str(e)}'
        }

def detect_suspicious_activity(audit_logs_table, person_id, event_type, ip_address, user_agent):
    """Detect suspicious activity patterns and trigger alerts"""
    try:
        # Define time window for analysis (last 1 hour)
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=1)
        
        # Query recent events for this person
        response = audit_logs_table.scan(
            FilterExpression='personId = :person_id AND #ts BETWEEN :start_time AND :end_time',
            ExpressionAttributeNames={'#ts': 'timestamp'},
            ExpressionAttributeValues={
                ':person_id': person_id,
                ':start_time': start_time.isoformat(),
                ':end_time': end_time.isoformat()
            }
        )
        
        events = response.get('Items', [])
        
        # Analyze for suspicious patterns
        suspicious_patterns = []
        
        # Pattern 1: Multiple failed login attempts
        failed_logins = [e for e in events if e.get('action') == 'LOGIN_FAILED']
        if len(failed_logins) >= 3:
            suspicious_patterns.append({
                'type': 'MULTIPLE_FAILED_LOGINS',
                'description': f'{len(failed_logins)} failed login attempts in the last hour',
                'severity': 'HIGH',
                'count': len(failed_logins)
            })
        
        # Pattern 2: Login from multiple IP addresses
        unique_ips = set()
        for event in events:
            if event.get('action') in ['LOGIN_SUCCESS', 'LOGIN_FAILED']:
                unique_ips.add(event.get('ipAddress', 'unknown'))
        
        if len(unique_ips) >= 3:
            suspicious_patterns.append({
                'type': 'MULTIPLE_IP_ADDRESSES',
                'description': f'Login attempts from {len(unique_ips)} different IP addresses',
                'severity': 'MEDIUM',
                'ips': list(unique_ips)
            })
        
        # Pattern 3: Rapid password changes
        password_changes = [e for e in events if 'PASSWORD_CHANGE' in e.get('action', '')]
        if len(password_changes) >= 2:
            suspicious_patterns.append({
                'type': 'RAPID_PASSWORD_CHANGES',
                'description': f'{len(password_changes)} password changes in the last hour',
                'severity': 'MEDIUM',
                'count': len(password_changes)
            })
        
        # Pattern 4: Unusual user agent patterns
        user_agents = set()
        for event in events:
            if event.get('userAgent') and event.get('userAgent') != 'unknown':
                user_agents.add(event.get('userAgent'))
        
        if len(user_agents) >= 3:
            suspicious_patterns.append({
                'type': 'MULTIPLE_USER_AGENTS',
                'description': f'Activity from {len(user_agents)} different browsers/devices',
                'severity': 'LOW',
                'agents': list(user_agents)
            })
        
        return suspicious_patterns
        
    except Exception as e:
        print(f"Error detecting suspicious activity: {str(e)}")
        return []

def send_admin_password_reset_email(email, user_name, admin_name, reset_type):
    """Send email notification for admin-initiated password reset"""
    try:
        if reset_type == 'temporary':
            subject = "Your password has been reset by an administrator"
            body = f"""
Hello {user_name},

Your password has been reset by an administrator ({admin_name}) and a temporary password has been generated for your account.

IMPORTANT SECURITY NOTICE:
• A temporary password has been created for your account
• You will be required to change this password on your next login
• Please contact the administrator to obtain your temporary password
• For security reasons, the temporary password is not included in this email

Next Steps:
1. Contact the administrator to get your temporary password
2. Log in to your account using the temporary password
3. You will be automatically prompted to create a new password
4. Choose a strong, unique password for your account

If you did not request this password reset, please contact your administrator immediately.

Security Information:
• This action was performed by: {admin_name}
• Date and time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
• If you have any concerns, please contact your system administrator

Best regards,
People Register Security Team
            """
        else:  # email reset
            subject = "Password reset link (Administrator initiated)"
            body = f"""
Hello {user_name},

An administrator ({admin_name}) has initiated a password reset for your account. You will receive a separate email with a secure password reset link.

IMPORTANT SECURITY NOTICE:
• This password reset was initiated by an administrator
• You will receive a password reset link in a separate email
• The reset link will expire in 1 hour for security
• Use the link to create a new password for your account

If you did not request this password reset, please contact your administrator immediately.

Security Information:
• This action was performed by: {admin_name}
• Date and time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
• If you have any concerns, please contact your system administrator

Best regards,
People Register Security Team
            """
        
        # Send email via SES
        response = ses_client.send_email(
            Source=os.environ.get('SES_FROM_EMAIL', 'noreply@people-register.local'),
            Destination={'ToAddresses': [email]},
            Message={
                'Subject': {
                    'Data': subject,
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Text': {
                        'Data': body,
                        'Charset': 'UTF-8'
                    }
                }
            }
        )
        
        return {
            'success': True,
            'message_id': response.get('MessageId'),
            'message': 'Admin password reset email sent successfully'
        }
        
    except Exception as e:
        print(f"Error sending admin password reset email: {str(e)}")
        return {'success': False, 'message': str(e)}

def get_password_change_history(people_table, audit_logs_table, event):
    """Get password change history for a user (dates only for privacy)"""
    try:
        # Extract user ID from query parameters or path
        query_params = event.get('queryStringParameters') or {}
        user_id = query_params.get('userId')
        
        if not user_id:
            return error_response(400, 'User ID is required')
        
        # Get person record
        try:
            response = people_table.get_item(Key={'id': user_id})
            person = response.get('Item')
            if not person:
                return error_response(404, 'User not found')
        except Exception as e:
            print(f"Error getting person: {str(e)}")
            return error_response(500, 'Error retrieving user information')
        
        # Get password history (dates only for privacy)
        password_history = person.get('passwordHistory', [])
        history_dates = []
        
        for entry in password_history:
            if 'changedAt' in entry:
                # Parse and format date for display
                try:
                    changed_date = datetime.fromisoformat(entry['changedAt'].replace('Z', '+00:00'))
                    history_dates.append({
                        'changedAt': changed_date.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'dateOnly': changed_date.strftime('%Y-%m-%d')
                    })
                except:
                    # Fallback for any date parsing issues
                    history_dates.append({
                        'changedAt': entry['changedAt'],
                        'dateOnly': entry['changedAt'][:10] if len(entry['changedAt']) >= 10 else entry['changedAt']
                    })
        
        # Add current password change date if available
        if person.get('lastPasswordChange'):
            try:
                last_change = datetime.fromisoformat(person['lastPasswordChange'].replace('Z', '+00:00'))
                history_dates.append({
                    'changedAt': last_change.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'dateOnly': last_change.strftime('%Y-%m-%d'),
                    'isCurrent': True
                })
            except:
                pass
        
        # Sort by date (most recent first)
        history_dates.sort(key=lambda x: x['changedAt'], reverse=True)
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps({
                'success': True,
                'passwordHistory': history_dates,
                'totalChanges': len(history_dates)
            })
        }
        
    except Exception as e:
        print(f"Error getting password history: {str(e)}")
        return error_response(500, 'Internal server error')

def change_password_first_time(people_table, audit_logs_table, event):
    """Handle first-time password change for new users"""
    try:
        body = json.loads(event.get('body', '{}'))
        current_password = body.get('currentPassword', '')
        new_password = body.get('newPassword', '')
        confirm_password = body.get('confirmPassword', '')
        user_id = body.get('userId', '')
        
        if not all([current_password, new_password, confirm_password, user_id]):
            return error_response(400, 'All password fields and user ID are required')
        
        if new_password != confirm_password:
            return error_response(400, 'New password and confirmation do not match')
        
        # Validate new password strength
        password_validation = validate_password_strength(new_password)
        if not password_validation['valid']:
            return error_response(400, f"Password does not meet requirements: {', '.join(password_validation['errors'])}")
        
        # Get client information
        client_ip = get_client_ip(event)
        user_agent = get_user_agent(event)
        
        # Get person record
        try:
            response = people_table.get_item(Key={'id': user_id})
            person = response.get('Item')
            if not person:
                return error_response(404, 'User not found')
        except Exception as e:
            print(f"Error getting person: {str(e)}")
            return error_response(500, 'Error retrieving user information')
        
        # Verify current password
        stored_hash = person.get('passwordHash')
        if not stored_hash or not verify_password(current_password, stored_hash):
            # Log failed password change attempt
            create_audit_log(
                audit_logs_table,
                user_id,
                'PASSWORD_CHANGE_FAILED',
                False,
                {'reason': 'invalid_current_password'},
                client_ip,
                user_agent
            )
            return error_response(401, 'Current password is incorrect')
        
        # Check if user is required to change password
        if not person.get('requirePasswordChange', False):
            return error_response(400, 'Password change is not required for this user')
        
        # Hash new password
        password_data = hash_password(new_password)
        
        # Update person's password and remove requirePasswordChange flag
        people_table.update_item(
            Key={'id': user_id},
            UpdateExpression='SET passwordHash = :hash, passwordSalt = :salt, lastPasswordChange = :timestamp, requirePasswordChange = :require_change',
            ExpressionAttributeValues={
                ':hash': password_data['hash'],
                ':salt': password_data['salt'],
                ':timestamp': datetime.utcnow().isoformat(),
                ':require_change': False
            }
        )
        
        # Log successful password change
        create_audit_log(
            audit_logs_table,
            user_id,
            'FIRST_TIME_PASSWORD_CHANGE',
            True,
            {'email': person['email']},
            client_ip,
            user_agent
        )
        
        # Send password changed confirmation email
        email_result = send_password_changed_email(
            person['email'],
            person.get('firstName', 'User'),
            datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            client_ip
        )
        
        if email_result['success']:
            print(f"Password changed confirmation email sent to: {person['email']}")
        else:
            print(f"Failed to send password changed email: {email_result['message']}")
        
        print(f"First-time password change completed for user: {user_id}")
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps({
                'success': True,
                'message': 'Password has been successfully changed. You can now access your account normally.'
            })
        }
        
    except Exception as e:
        print(f"Error changing password: {str(e)}")
        return error_response(500, 'Internal server error')

def preview_password_reset_email(event):
    """Preview password reset email content for testing"""
    try:
        query_params = event.get('queryStringParameters') or {}
        email = query_params.get('email', 'test@example.com')
        first_name = query_params.get('firstName', 'Test User')
        reset_token = query_params.get('token', 'sample-reset-token-123')
        
        frontend_url = os.environ.get('FRONTEND_URL', 'https://d28z2il3z2vmpc.cloudfront.net')
        reset_link = f"{frontend_url}/reset-password?token={reset_token}"
        
        # Generate email content
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }}
                .button {{ display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
                .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Password Reset Request</h1>
                </div>
                <div class="content">
                    <h2>Hello {first_name},</h2>
                    <p>We received a request to reset your password for your People Register account.</p>
                    <div style="text-align: center;">
                        <a href="{reset_link}" class="button">Reset My Password</a>
                    </div>
                    <div class="warning">
                        <strong>⚠️ Important:</strong>
                        <ul>
                            <li>This link will expire in 1 hour</li>
                            <li>This link can only be used once</li>
                            <li>If you didn't request this reset, please ignore this email</li>
                        </ul>
                    </div>
                    <p>If the button doesn't work, copy this link: {reset_link}</p>
                    <p><strong>Email Details:</strong></p>
                    <ul>
                        <li>To: {email}</li>
                        <li>Subject: Reset Your Password - People Register</li>
                        <li>Reset Token: {reset_token}</li>
                    </ul>
                </div>
            </div>
        </body>
        </html>
        """
        
        return {
            'statusCode': 200,
            'headers': {
                **get_cors_headers(),
                'Content-Type': 'text/html'
            },
            'body': html_body
        }
        
    except Exception as e:
        print(f"Error previewing email: {str(e)}")
        return error_response(500, 'Internal server error')
    """Extract client IP from event"""
    headers = event.get('headers', {})
    
    # Check for forwarded IP
    forwarded_for = headers.get('x-forwarded-for') or headers.get('X-Forwarded-For')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    
    # Check for real IP
    real_ip = headers.get('x-real-ip') or headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    # Fall back to source IP
    return event.get('requestContext', {}).get('identity', {}).get('sourceIp', 'unknown')

def get_user_agent(event):
    """Extract user agent from event"""
    headers = event.get('headers', {})
    return headers.get('user-agent') or headers.get('User-Agent') or 'unknown'

# Password reset API functions
def initiate_password_reset(people_table, password_reset_tokens_table, audit_logs_table, event):
    """Initiate password reset process"""
    try:
        body = json.loads(event.get('body', '{}'))
        email = body.get('email', '').strip().lower()
        
        if not email:
            return error_response(400, 'Email address is required')
        
        # Get client information
        client_ip = get_client_ip(event)
        user_agent = get_user_agent(event)
        
        # Check IP-based rate limiting for password reset
        rate_limit_status = check_ip_rate_limit(audit_logs_table, client_ip, 'password_reset')
        if rate_limit_status.get('blocked'):
            # Log rate limit violation
            log_rate_limit_attempt(audit_logs_table, client_ip, 'password_reset', user_agent)
            
            return {
                'statusCode': 429,
                'headers': {
                    **get_cors_headers(),
                    'Retry-After': str(rate_limit_status.get('retry_after_minutes', 60) * 60)
                },
                'body': json.dumps({
                    'error': 'Too many password reset attempts',
                    'message': rate_limit_status.get('reason', 'Rate limit exceeded'),
                    'retry_after_minutes': rate_limit_status.get('retry_after_minutes', 60)
                })
            }
        
        # Check if person exists (don't reveal if email exists for security)
        person = get_person_by_email(people_table, email)
        
        # Always return success message for security
        success_message = "If the email address exists in our system, you will receive a password reset link."
        
        if person:
            # Generate reset token
            reset_token = generate_reset_token()
            expires_at = get_token_expiry()
            
            # Store reset token
            token_record = {
                'resetToken': reset_token,
                'personId': person['id'],
                'email': email,
                'expiresAt': expires_at,
                'isUsed': False,
                'createdAt': datetime.utcnow().isoformat(),
                'ipAddress': client_ip,
                'userAgent': user_agent
            }
            
            password_reset_tokens_table.put_item(Item=token_record)
            
            # Log security event
            create_audit_log(
                audit_logs_table,
                person['id'],
                'PASSWORD_RESET_REQUESTED',
                True,
                {'email': email},
                client_ip,
                user_agent
            )
            
            # Send password reset email with enhanced tracking
            email_result = send_password_reset_email(
                recipient_email=email,
                first_name=person.get('firstName', 'User'),
                reset_token=reset_token,
                ip_address=client_ip,
                user_agent=user_agent
            )
            
            if email_result['success']:
                print(f"Password reset email sent successfully to: {email}, Email ID: {email_result['email_id']}")
                
                # Log email delivery attempt
                create_audit_log(
                    audit_logs_table,
                    person['id'],
                    'PASSWORD_RESET_EMAIL_SENT',
                    True,
                    {
                        'email': email,
                        'email_id': email_result['email_id'],
                        'reset_token_id': reset_token
                    },
                    client_ip,
                    user_agent
                )
            else:
                print(f"Failed to send password reset email: {email_result['message']}")
                
                # Log email delivery failure
                create_audit_log(
                    audit_logs_table,
                    person['id'],
                    'PASSWORD_RESET_EMAIL_FAILED',
                    False,
                    {
                        'email': email,
                        'error': email_result['error'],
                        'reset_token_id': reset_token
                    },
                    client_ip,
                    user_agent
                )
            
            print(f"Password reset initiated for email: {email}")
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps({
                'success': True,
                'message': success_message
            })
        }
        
    except Exception as e:
        print(f"Error initiating password reset: {str(e)}")
        return error_response(500, 'Internal server error')

def validate_reset_token(password_reset_tokens_table, token):
    """Validate a password reset token"""
    try:
        response = password_reset_tokens_table.get_item(
            Key={'resetToken': token}
        )
        
        token_record = response.get('Item')
        if not token_record:
            return {
                'statusCode': 400,
                'headers': get_cors_headers(),
                'body': json.dumps({
                    'success': False,
                    'message': 'Invalid or expired reset link.',
                    'token_valid': False
                })
            }
        
        # Check if token is expired
        if is_token_expired(token_record['expiresAt']):
            return {
                'statusCode': 400,
                'headers': get_cors_headers(),
                'body': json.dumps({
                    'success': False,
                    'message': 'Reset link has expired. Please request a new one.',
                    'token_valid': False
                })
            }
        
        # Check if token has been used
        if token_record.get('isUsed', False):
            return {
                'statusCode': 400,
                'headers': get_cors_headers(),
                'body': json.dumps({
                    'success': False,
                    'message': 'Reset link has already been used. Please request a new one.',
                    'token_valid': False
                })
            }
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps({
                'success': True,
                'message': 'Reset link is valid.',
                'token_valid': True,
                'expires_at': token_record['expiresAt']
            })
        }
        
    except Exception as e:
        print(f"Error validating reset token: {str(e)}")
        return error_response(500, 'Internal server error')

def reset_password_with_token(people_table, password_reset_tokens_table, audit_logs_table, event):
    """Reset password using a valid reset token"""
    try:
        body = json.loads(event.get('body', '{}'))
        reset_token = body.get('resetToken', body.get('reset_token', '')).strip()
        new_password = body.get('newPassword', body.get('new_password', ''))
        confirm_password = body.get('confirmPassword', body.get('confirm_password', ''))
        
        if not reset_token or not new_password:
            return error_response(400, 'Reset token and new password are required')
        
        if confirm_password and new_password != confirm_password:
            return error_response(400, 'New password and confirmation do not match')
        
        # Validate password policy
        password_errors = validate_password_policy(new_password)
        if password_errors:
            return error_response(400, f"Password validation failed: {', '.join(password_errors)}")
        
        # Get client information
        client_ip = get_client_ip(event)
        user_agent = get_user_agent(event)
        
        # Validate token
        token_response = validate_reset_token(password_reset_tokens_table, reset_token)
        if token_response['statusCode'] != 200:
            return token_response
        
        # Get token record
        response = password_reset_tokens_table.get_item(
            Key={'resetToken': reset_token}
        )
        token_record = response.get('Item')
        
        if not token_record:
            return error_response(400, 'Invalid reset token')
        
        # Get person record
        person_response = people_table.get_item(
            Key={'id': token_record['personId']}
        )
        person = person_response.get('Item')
        
        if not person:
            return error_response(400, 'User account not found')
        
        # Hash new password
        password_data = hash_password(new_password)
        
        # Update person's password
        people_table.update_item(
            Key={'id': person['id']},
            UpdateExpression='SET passwordHash = :hash, passwordSalt = :salt, lastPasswordChange = :timestamp, requirePasswordChange = :require_change',
            ExpressionAttributeValues={
                ':hash': password_data['hash'],
                ':salt': password_data['salt'],
                ':timestamp': datetime.utcnow().isoformat(),
                ':require_change': False
            }
        )
        
        # Mark token as used
        password_reset_tokens_table.update_item(
            Key={'resetToken': reset_token},
            UpdateExpression='SET isUsed = :used',
            ExpressionAttributeValues={':used': True}
        )
        
        # Log security event
        create_audit_log(
            audit_logs_table,
            person['id'],
            'PASSWORD_RESET_COMPLETED',
            True,
            {'reset_token': reset_token},
            client_ip,
            user_agent
        )
        
        # Send password changed confirmation email with enhanced tracking
        email_result = send_password_changed_email(
            recipient_email=person['email'],
            first_name=person.get('firstName', 'User'),
            change_type='Password Reset',
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        if email_result['success']:
            print(f"Password change confirmation email sent to: {person['email']}, Email ID: {email_result['email_id']}")
            
            # Log email delivery success
            create_audit_log(
                audit_logs_table,
                person['id'],
                'PASSWORD_CHANGE_EMAIL_SENT',
                True,
                {
                    'email': person['email'],
                    'email_id': email_result['email_id'],
                    'change_type': 'Password Reset'
                },
                client_ip,
                user_agent
            )
        else:
            print(f"Failed to send password change confirmation email: {email_result['message']}")
            
            # Log email delivery failure
            create_audit_log(
                audit_logs_table,
                person['id'],
                'PASSWORD_CHANGE_EMAIL_FAILED',
                False,
                {
                    'email': person['email'],
                    'error': email_result['error'],
                    'change_type': 'Password Reset'
                },
                client_ip,
                user_agent
            )
        
        if email_result['success']:
            print(f"Password changed confirmation email sent to: {person['email']}")
        else:
            print(f"Failed to send password changed email: {email_result['message']}")
            
        if completion_email_result['success']:
            print(f"Password reset completion email sent to: {person['email']}")
        else:
            print(f"Failed to send password reset completion email: {completion_email_result['message']}")
        
        print(f"Password reset completed for person: {person['id']}")
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps({
                'success': True,
                'message': 'Password has been successfully reset. You can now log in with your new password.'
            })
        }
        
    except Exception as e:
        print(f"Error resetting password: {str(e)}")
        return error_response(500, 'Internal server error')

def cleanup_expired_tokens(password_reset_tokens_table):
    """Clean up expired reset tokens"""
    try:
        # Scan for expired tokens
        cutoff_time = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        
        response = password_reset_tokens_table.scan(
            FilterExpression='expiresAt < :cutoff',
            ExpressionAttributeValues={':cutoff': cutoff_time}
        )
        
        expired_tokens = response.get('Items', [])
        cleaned_count = 0
        
        # Delete expired tokens
        for token in expired_tokens:
            password_reset_tokens_table.delete_item(
                Key={'resetToken': token['resetToken']}
            )
            cleaned_count += 1
        
        print(f"Cleaned up {cleaned_count} expired tokens")
        
        return {
            'statusCode': 200,
            'headers': get_cors_headers(),
            'body': json.dumps({
                'success': True,
                'message': f'Cleaned up {cleaned_count} expired tokens',
                'cleaned_count': cleaned_count
            })
        }
        
    except Exception as e:
        print(f"Error cleaning up expired tokens: {str(e)}")
        return error_response(500, 'Internal server error')

def lambda_handler(event, context):
    try:
        print(f"Lambda handler started - Enhanced Password Service Available: {SERVICE_AVAILABLE}")
        print(f"Event: {json.dumps(event)}")
        
        # Get table names from environment
        people_table_name = os.environ.get('PEOPLE_TABLE_NAME', 'PeopleTable')
        projects_table_name = os.environ.get('PROJECTS_TABLE_NAME', 'ProjectsTable')
        subscriptions_table_name = os.environ.get('SUBSCRIPTIONS_TABLE_NAME', 'SubscriptionsTable')
        password_reset_tokens_table_name = os.environ.get('PASSWORD_RESET_TOKENS_TABLE_NAME', 'PasswordResetTokensTable')
        audit_logs_table_name = os.environ.get('AUDIT_LOGS_TABLE_NAME', 'AuditLogsTable')
        
        print(f"Table names - People: {people_table_name}, Projects: {projects_table_name}")
        
        people_table = dynamodb.Table(people_table_name)
        projects_table = dynamodb.Table(projects_table_name)
        subscriptions_table = dynamodb.Table(subscriptions_table_name)
        password_reset_tokens_table = dynamodb.Table(password_reset_tokens_table_name)
        audit_logs_table = dynamodb.Table(audit_logs_table_name)
        
        # Extract HTTP method and path
        http_method = event.get('httpMethod', 'GET')
        path = event.get('path', '/')
        path_parameters = event.get('pathParameters') or {}
        
        print(f"Processing request: {http_method} {path}")
        
    except Exception as e:
        print(f"Error in lambda handler initialization: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return {
            'statusCode': 500,
            'headers': get_cors_headers(),
            'body': json.dumps({
                'error': 'Lambda initialization failed',
                'message': str(e)
            })
        }
    
    try:
        # Health check
        if path == '/health':
            return {
                'statusCode': 200,
                'headers': get_cors_headers(),
                'body': json.dumps({'status': 'healthy', 'service': 'people-register-api-global-with-projects'}, cls=DecimalEncoder)
            }
        
        # PEOPLE ENDPOINTS (existing)
        elif path == '/people':
            if http_method == 'GET':
                response = people_table.scan()
                people = response.get('Items', [])
                return {
                    'statusCode': 200,
                    'headers': get_cors_headers(),
                    'body': json.dumps(people, cls=DecimalEncoder)
                }
            
            elif http_method == 'POST':
                return create_person(people_table, event)
        
        elif path.startswith('/people/'):
            person_id = path_parameters.get('id')
            if not person_id:
                return error_response(400, 'Person ID is required')
            
            if http_method == 'GET':
                return get_person(people_table, person_id)
            elif http_method == 'PUT':
                return update_person(people_table, person_id, event)
            elif http_method == 'DELETE':
                return delete_person(people_table, person_id)
        
        # PROJECTS ENDPOINTS (new)
        elif path == '/projects':
            if http_method == 'GET':
                return get_projects(projects_table)
            elif http_method == 'POST':
                return create_project(projects_table, event)
        
        elif path.startswith('/projects/'):
            project_id = path_parameters.get('id')
            if not project_id:
                return error_response(400, 'Project ID is required')
            
            # Handle nested routes
            if path.endswith('/subscribers'):
                return get_project_subscribers(subscriptions_table, people_table, project_id)
            elif '/subscribe/' in path:
                person_id = path.split('/subscribe/')[-1]
                return subscribe_person_to_project(subscriptions_table, project_id, person_id, event)
            elif '/unsubscribe/' in path:
                person_id = path.split('/unsubscribe/')[-1]
                return unsubscribe_person_from_project(subscriptions_table, project_id, person_id)
            else:
                if http_method == 'GET':
                    return get_project(projects_table, project_id)
                elif http_method == 'PUT':
                    return update_project(projects_table, project_id, event)
                elif http_method == 'DELETE':
                    return delete_project(projects_table, subscriptions_table, project_id)
        
        # SUBSCRIPTIONS ENDPOINTS (new)
        elif path == '/subscriptions':
            if http_method == 'GET':
                return get_subscriptions(subscriptions_table)
            elif http_method == 'POST':
                return create_subscription(subscriptions_table, event)
        
        elif path.startswith('/subscriptions/'):
            subscription_id = path_parameters.get('id')
            if http_method == 'DELETE':
                return delete_subscription(subscriptions_table, subscription_id)
        
        # PASSWORD RESET ENDPOINTS (simplified routing)
        elif path == '/auth/login':
            if http_method == 'POST':
                return login_user(people_table, audit_logs_table, event)
            elif http_method == 'OPTIONS':
                return {
                    'statusCode': 200,
                    'headers': get_cors_headers(),
                    'body': json.dumps({'message': 'CORS preflight successful'})
                }
            else:
                return error_response(405, 'Method not allowed')
                
        elif path == '/auth/logout':
            if http_method == 'POST':
                return logout_user(event)
            elif http_method == 'OPTIONS':
                return {
                    'statusCode': 200,
                    'headers': get_cors_headers(),
                    'body': json.dumps({'message': 'CORS preflight successful'})
                }
            else:
                return error_response(405, 'Method not allowed')
                
        elif path == '/auth/me':
            if http_method == 'GET':
                return get_current_user(people_table, event)
            elif http_method == 'OPTIONS':
                return {
                    'statusCode': 200,
                    'headers': get_cors_headers(),
                    'body': json.dumps({'message': 'CORS preflight successful'})
                }
            else:
                return error_response(405, 'Method not allowed')
                
        elif path == '/auth/password-reset':
            if http_method == 'POST':
                # Determine operation based on request body
                body = json.loads(event.get('body', '{}'))
                operation = body.get('operation', 'initiate')
                
                # Debug logging
                print(f"🔍 DEBUG: Received operation: '{operation}', body: {body}")
                
                if operation == 'initiate':
                    return initiate_password_reset(people_table, password_reset_tokens_table, audit_logs_table, event)
                elif operation == 'complete':
                    return reset_password_with_token(people_table, password_reset_tokens_table, audit_logs_table, event)
                elif operation == 'login':
                    # Handle login through password-reset endpoint to avoid API Gateway limits
                    print(f"🔑 DEBUG: Processing login for email: {body.get('email', 'unknown')}")
                    return login_user(people_table, audit_logs_table, event)
                elif operation == 'change-first-time':
                    # Handle first-time password change through password-reset endpoint
                    return change_password_first_time(people_table, audit_logs_table, event)
                elif operation == 'change-profile':
                    # Handle profile password change
                    return change_password_profile(people_table, audit_logs_table, event)
                elif operation == 'admin-reset':
                    # Handle admin-initiated password reset
                    return admin_reset_password(people_table, password_reset_tokens_table, audit_logs_table, event)
                else:
                    return error_response(400, 'Invalid operation')
            
            elif http_method == 'GET':
                # Handle different GET operations based on query parameters
                query_params = event.get('queryStringParameters') or {}
                
                if 'token' in query_params:
                    # Token validation
                    return validate_reset_token(password_reset_tokens_table, query_params['token'])
                elif 'userId' in query_params and query_params.get('action') == 'history':
                    # Password change history
                    return get_password_change_history(people_table, audit_logs_table, event)
                elif query_params.get('action') == 'security-dashboard':
                    # Security dashboard data
                    return get_security_dashboard(audit_logs_table, event)
                elif query_params.get('action') == 'security-events':
                    # Security events list
                    return get_security_events(audit_logs_table, event)
                else:
                    return error_response(400, 'Invalid GET request parameters')
        
        elif path == '/admin/password-reset':
            if http_method == 'POST':
                return cleanup_expired_tokens(password_reset_tokens_table)
        
        # EMAIL TESTING ENDPOINTS
        elif path == '/test/email-preview':
            if http_method == 'GET':
                return preview_password_reset_email(event)
        
        # ADMIN ENDPOINTS (existing)
        elif path == '/admin/dashboard':
            return get_admin_dashboard(people_table, projects_table, subscriptions_table)
        
        elif path == '/admin/unlock-account':
            if http_method == 'POST':
                return admin_unlock_account(people_table, audit_logs_table, event)
        
        elif path == '/admin/account-status':
            if http_method == 'GET':
                query_params = event.get('queryStringParameters') or {}
                person_id = query_params.get('personId')
                if person_id:
                    status = get_account_lockout_status(people_table, person_id)
                    return {
                        'statusCode': 200,
                        'headers': get_cors_headers(),
                        'body': json.dumps(status)
                    }
                else:
                    return error_response(400, 'Person ID is required')
        
        elif path == '/admin/email-status':
            if http_method == 'GET':
                query_params = event.get('queryStringParameters') or {}
                email_id = query_params.get('emailId')
                if email_id:
                    status = email_service.get_email_status(email_id)
                    return {
                        'statusCode': 200,
                        'headers': get_cors_headers(),
                        'body': json.dumps(status or {'error': 'Email not found'})
                    }
                else:
                    return error_response(400, 'Email ID is required')
        
        elif path == '/admin/email-statistics':
            if http_method == 'GET':
                query_params = event.get('queryStringParameters') or {}
                days = int(query_params.get('days', 7))
                statistics = email_service.get_email_statistics(days)
                return {
                    'statusCode': 200,
                    'headers': get_cors_headers(),
                    'body': json.dumps(statistics)
                }
        
        elif path == '/auth/refresh-token':
            if http_method == 'POST':
                body = json.loads(event.get('body', '{}'))
                refresh_token_value = body.get('refreshToken', '')
                
                if not refresh_token_value:
                    return error_response(400, 'Refresh token is required')
                
                # Refresh access token
                new_tokens = refresh_token(refresh_token_value)
                
                if new_tokens:
                    return {
                        'statusCode': 200,
                        'headers': get_cors_headers(),
                        'body': json.dumps({
                            'success': True,
                            'tokens': new_tokens
                        })
                    }
                else:
                    return error_response(401, SECURITY_ERROR_CODES['SESSION_EXPIRED'])
        
        elif path == '/auth/logout':
            if http_method == 'POST':
                # Extract session ID from token
                auth_header = event.get('headers', {}).get('Authorization', '')
                if auth_header.startswith('Bearer '):
                    token = auth_header[7:]
                    try:
                        # Basic token decoding for fallback
                        import base64
                        payload = json.loads(base64.b64decode(token).decode())
                        
                        user_id = payload.get('user_id')
                        
                        if user_id:
                            return {
                                'statusCode': 200,
                                'headers': get_cors_headers(),
                                'body': json.dumps({
                                    'success': True,
                                    'message': 'Logged out successfully (basic implementation)'
                                })
                            }
                    except Exception as e:
                        print(f"Token decode error: {str(e)}")
                        pass
                
                return error_response(400, 'Invalid session')
        
        elif path == '/auth/logout-all-devices':
            if http_method == 'POST':
                # Extract user ID from token
                auth_header = event.get('headers', {}).get('Authorization', '')
                if auth_header.startswith('Bearer '):
                    token = auth_header[7:]
                    try:
                        # Basic token decoding for fallback
                        import base64
                        payload = json.loads(base64.b64decode(token).decode())
                        
                        user_id = payload.get('user_id')
                        
                        if user_id:
                            return {
                                'statusCode': 200,
                                'headers': get_cors_headers(),
                                'body': json.dumps({
                                    'success': True,
                                    'message': 'Logged out from all devices (basic implementation)',
                                    'invalidated_sessions': 0
                                })
                            }
                    except Exception as e:
                        print(f"Token decode error: {str(e)}")
                        pass
                
                return error_response(400, 'Invalid session')
        
        elif path == '/auth/active-sessions':
            if http_method == 'GET':
                # Extract user ID from token
                auth_header = event.get('headers', {}).get('Authorization', '')
                if auth_header.startswith('Bearer '):
                    token = auth_header[7:]
                    try:
                        # Basic token decoding for fallback
                        import base64
                        payload = json.loads(base64.b64decode(token).decode())
                        
                        user_id = payload.get('user_id')
                        
                        if user_id:
                            return {
                                'statusCode': 200,
                                'headers': get_cors_headers(),
                                'body': json.dumps({
                                    'success': True,
                                    'sessions': []  # Empty for basic implementation
                                })
                            }
                    except Exception as e:
                        print(f"Token decode error: {str(e)}")
                        pass
                
                return error_response(400, 'Invalid session')
        
        elif path == '/admin/email-templates':
            if http_method == 'GET':
                # Return available email templates
                templates = {
                    'welcome': {
                        'name': 'Welcome Email',
                        'description': 'Sent when a new account is created',
                        'variables': ['FIRST_NAME', 'EMAIL', 'TEMPORARY_PASSWORD', 'LOGIN_URL']
                    },
                    'password_reset': {
                        'name': 'Password Reset',
                        'description': 'Sent when password reset is requested',
                        'variables': ['FIRST_NAME', 'RESET_URL', 'EXPIRY_DATE', 'REQUEST_DATE', 'IP_ADDRESS', 'USER_AGENT']
                    },
                    'password_changed': {
                        'name': 'Password Changed',
                        'description': 'Sent when password is successfully changed',
                        'variables': ['FIRST_NAME', 'CHANGE_DATE', 'IP_ADDRESS', 'USER_AGENT', 'CHANGE_TYPE']
                    }
                }
                return {
                    'statusCode': 200,
                    'headers': get_cors_headers(),
                    'body': json.dumps(templates)
                }
        
        # Default response for unmatched routes
        return error_response(404, 'Route not found')
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return error_response(500, 'Internal server error')

def get_client_ip(event):
    """Extract client IP from event"""
    return event.get('requestContext', {}).get('identity', {}).get('sourceIp', 'unknown')

def get_user_agent(event):
    """Extract user agent from event"""
    headers = event.get('headers', {})
    return headers.get('User-Agent', headers.get('user-agent', 'unknown'))

def get_cors_headers():
    return {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key'
    }

def error_response(status_code, message):
    return {
        'statusCode': status_code,
        'headers': get_cors_headers(),
        'body': json.dumps({'error': message}, cls=DecimalEncoder)
    }

# PEOPLE FUNCTIONS (existing, updated)
def create_person(people_table, event):
    body = json.loads(event.get('body', '{}'))
    person_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    
    # Address structure for global use
    address = body.get('address', {})
    if address:
        clean_address = {
            'street': address.get('street', ''),
            'city': address.get('city', ''),
            'state': address.get('state', ''),
            'country': address.get('country', '')
        }
        if address.get('postalCode'):
            clean_address['postalCode'] = address.get('postalCode')
    else:
        clean_address = {}
    
    person = {
        'id': person_id,
        'firstName': body.get('firstName'),
        'lastName': body.get('lastName'),
        'email': body.get('email'),
        'phone': body.get('phone'),
        'dateOfBirth': body.get('dateOfBirth'),
        'address': clean_address,
        'createdAt': now,
        'updatedAt': now,
        # Password-related fields (will be populated by password management functions)
        'passwordHash': None,
        'passwordSalt': None,
        'requirePasswordChange': True,  # Default to true for new accounts
        'lastPasswordChange': None,
        'passwordHistory': [],  # Store last 5 password hashes
        'failedLoginAttempts': 0,
        'accountLockedUntil': None,
        'lastLoginAt': None,
        'isActive': True
    }
    
    people_table.put_item(Item=person)
    
    return {
        'statusCode': 201,
        'headers': get_cors_headers(),
        'body': json.dumps(person, cls=DecimalEncoder)
    }

def get_person(people_table, person_id):
    response = people_table.get_item(Key={'id': person_id})
    if 'Item' not in response:
        return error_response(404, 'Person not found')
    
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(response['Item'], cls=DecimalEncoder)
    }

def update_person(people_table, person_id, event):
    body = json.loads(event.get('body', '{}'))
    now = datetime.utcnow().isoformat()
    
    response = people_table.get_item(Key={'id': person_id})
    if 'Item' not in response:
        return error_response(404, 'Person not found')
    
    person = response['Item']
    
    # Handle address update for global use
    if body.get('address'):
        address = body.get('address', {})
        clean_address = {
            'street': address.get('street', ''),
            'city': address.get('city', ''),
            'state': address.get('state', ''),
            'country': address.get('country', '')
        }
        if address.get('postalCode'):
            clean_address['postalCode'] = address.get('postalCode')
        person['address'] = clean_address
    
    person.update({
        'firstName': body.get('firstName', person.get('firstName')),
        'lastName': body.get('lastName', person.get('lastName')),
        'email': body.get('email', person.get('email')),
        'phone': body.get('phone', person.get('phone')),
        'dateOfBirth': body.get('dateOfBirth', person.get('dateOfBirth')),
        'updatedAt': now
    })
    
    people_table.put_item(Item=person)
    
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(person, cls=DecimalEncoder)
    }

def delete_person(people_table, person_id):
    response = people_table.delete_item(
        Key={'id': person_id},
        ReturnValues='ALL_OLD'
    )
    
    if 'Attributes' not in response:
        return error_response(404, 'Person not found')
    
    return {
        'statusCode': 204,
        'headers': get_cors_headers(),
        'body': ''
    }

# PROJECT FUNCTIONS (new)
def get_projects(projects_table):
    response = projects_table.scan()
    projects = response.get('Items', [])
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(projects, cls=DecimalEncoder)
    }

def create_project(projects_table, event):
    body = json.loads(event.get('body', '{}'))
    project_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    
    project = {
        'id': project_id,
        'name': body.get('name'),
        'description': body.get('description', ''),
        'status': body.get('status', 'active'),
        'createdBy': body.get('createdBy', 'admin'),
        'maxParticipants': body.get('maxParticipants'),
        'startDate': body.get('startDate'),
        'endDate': body.get('endDate'),
        'createdAt': now,
        'updatedAt': now
    }
    
    projects_table.put_item(Item=project)
    
    return {
        'statusCode': 201,
        'headers': get_cors_headers(),
        'body': json.dumps(project, cls=DecimalEncoder)
    }

def get_project(projects_table, project_id):
    response = projects_table.get_item(Key={'id': project_id})
    if 'Item' not in response:
        return error_response(404, 'Project not found')
    
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(response['Item'], cls=DecimalEncoder)
    }

def update_project(projects_table, project_id, event):
    body = json.loads(event.get('body', '{}'))
    now = datetime.utcnow().isoformat()
    
    response = projects_table.get_item(Key={'id': project_id})
    if 'Item' not in response:
        return error_response(404, 'Project not found')
    
    project = response['Item']
    project.update({
        'name': body.get('name', project.get('name')),
        'description': body.get('description', project.get('description')),
        'status': body.get('status', project.get('status')),
        'maxParticipants': body.get('maxParticipants', project.get('maxParticipants')),
        'startDate': body.get('startDate', project.get('startDate')),
        'endDate': body.get('endDate', project.get('endDate')),
        'updatedAt': now
    })
    
    projects_table.put_item(Item=project)
    
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(project, cls=DecimalEncoder)
    }

def delete_project(projects_table, subscriptions_table, project_id):
    # First, delete all subscriptions for this project
    response = subscriptions_table.query(
        IndexName='ProjectIndex',
        KeyConditionExpression='projectId = :projectId',
        ExpressionAttributeValues={':projectId': project_id}
    )
    
    for subscription in response.get('Items', []):
        subscriptions_table.delete_item(Key={'id': subscription['id']})
    
    # Then delete the project
    response = projects_table.delete_item(
        Key={'id': project_id},
        ReturnValues='ALL_OLD'
    )
    
    if 'Attributes' not in response:
        return error_response(404, 'Project not found')
    
    return {
        'statusCode': 204,
        'headers': get_cors_headers(),
        'body': ''
    }

# SUBSCRIPTION FUNCTIONS (new)
def get_subscriptions(subscriptions_table):
    response = subscriptions_table.scan()
    subscriptions = response.get('Items', [])
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(subscriptions, cls=DecimalEncoder)
    }

def create_subscription(subscriptions_table, event):
    body = json.loads(event.get('body', '{}'))
    subscription_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    
    subscription = {
        'id': subscription_id,
        'projectId': body.get('projectId'),
        'personId': body.get('personId'),
        'status': body.get('status', 'active'),
        'subscribedAt': now,
        'subscribedBy': body.get('subscribedBy', 'admin'),
        'notes': body.get('notes', '')
    }
    
    subscriptions_table.put_item(Item=subscription)
    
    return {
        'statusCode': 201,
        'headers': get_cors_headers(),
        'body': json.dumps(subscription, cls=DecimalEncoder)
    }

def delete_subscription(subscriptions_table, subscription_id):
    response = subscriptions_table.delete_item(
        Key={'id': subscription_id},
        ReturnValues='ALL_OLD'
    )
    
    if 'Attributes' not in response:
        return error_response(404, 'Subscription not found')
    
    return {
        'statusCode': 204,
        'headers': get_cors_headers(),
        'body': ''
    }

def subscribe_person_to_project(subscriptions_table, project_id, person_id, event):
    body = json.loads(event.get('body', '{}'))
    subscription_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    
    subscription = {
        'id': subscription_id,
        'projectId': project_id,
        'personId': person_id,
        'status': 'active',
        'subscribedAt': now,
        'subscribedBy': body.get('subscribedBy', 'admin'),
        'notes': body.get('notes', '')
    }
    
    subscriptions_table.put_item(Item=subscription)
    
    return {
        'statusCode': 201,
        'headers': get_cors_headers(),
        'body': json.dumps(subscription, cls=DecimalEncoder)
    }

def unsubscribe_person_from_project(subscriptions_table, project_id, person_id):
    # Find the subscription
    response = subscriptions_table.query(
        IndexName='ProjectIndex',
        KeyConditionExpression='projectId = :projectId',
        ExpressionAttributeValues={':projectId': project_id}
    )
    
    subscription_to_delete = None
    for subscription in response.get('Items', []):
        if subscription['personId'] == person_id:
            subscription_to_delete = subscription
            break
    
    if not subscription_to_delete:
        return error_response(404, 'Subscription not found')
    
    subscriptions_table.delete_item(Key={'id': subscription_to_delete['id']})
    
    return {
        'statusCode': 204,
        'headers': get_cors_headers(),
        'body': ''
    }

def get_project_subscribers(subscriptions_table, people_table, project_id):
    # Get all subscriptions for this project
    response = subscriptions_table.query(
        IndexName='ProjectIndex',
        KeyConditionExpression='projectId = :projectId',
        ExpressionAttributeValues={':projectId': project_id}
    )
    
    subscribers = []
    for subscription in response.get('Items', []):
        # Get person details
        person_response = people_table.get_item(Key={'id': subscription['personId']})
        if 'Item' in person_response:
            subscriber = person_response['Item']
            subscriber['subscriptionId'] = subscription['id']
            subscriber['subscriptionStatus'] = subscription['status']
            subscriber['subscribedAt'] = subscription['subscribedAt']
            subscribers.append(subscriber)
    
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(subscribers, cls=DecimalEncoder)
    }

def get_admin_dashboard(people_table, projects_table, subscriptions_table):
    # Get counts
    people_response = people_table.scan(Select='COUNT')
    projects_response = projects_table.scan(Select='COUNT')
    subscriptions_response = subscriptions_table.scan(Select='COUNT')
    
    dashboard_data = {
        'totalPeople': people_response.get('Count', 0),
        'totalProjects': projects_response.get('Count', 0),
        'totalSubscriptions': subscriptions_response.get('Count', 0),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    return {
        'statusCode': 200,
        'headers': get_cors_headers(),
        'body': json.dumps(dashboard_data, cls=DecimalEncoder)
    }
