import json
import boto3
import uuid
import os
import bcrypt  # Re-enabled with Linux-compatible version
from datetime import datetime, timedelta
from decimal import Decimal
import secrets
import string

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
def send_password_reset_email(to_email, first_name, reset_token):
    """Send password reset email via AWS SES"""
    try:
        frontend_url = os.environ.get('FRONTEND_URL', 'https://d28z2il3z2vmpc.cloudfront.net')
        from_email = os.environ.get('SES_FROM_EMAIL', 'noreply@people-register.local')
        reset_link = f"{frontend_url}/reset-password?token={reset_token}"
        
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
        
        We received a request to reset your password for your People Register account.
        
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
                    'Data': 'Reset Your Password - People Register',
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
            
            # Send password reset email
            email_result = send_password_reset_email(
                email, 
                person.get('firstName', 'User'), 
                reset_token
            )
            
            if email_result['success']:
                print(f"Password reset email sent successfully to: {email}")
            else:
                print(f"Failed to send password reset email: {email_result['message']}")
            
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
        reset_token = body.get('reset_token', '').strip()
        new_password = body.get('new_password', '')
        
        if not reset_token or not new_password:
            return error_response(400, 'Reset token and new password are required')
        
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
    print(f"Event: {json.dumps(event)}")
    
    # Get table names from environment
    people_table_name = os.environ.get('PEOPLE_TABLE_NAME', 'PeopleTable')
    projects_table_name = os.environ.get('PROJECTS_TABLE_NAME', 'ProjectsTable')
    subscriptions_table_name = os.environ.get('SUBSCRIPTIONS_TABLE_NAME', 'SubscriptionsTable')
    password_reset_tokens_table_name = os.environ.get('PASSWORD_RESET_TOKENS_TABLE_NAME', 'PasswordResetTokensTable')
    audit_logs_table_name = os.environ.get('AUDIT_LOGS_TABLE_NAME', 'AuditLogsTable')
    
    people_table = dynamodb.Table(people_table_name)
    projects_table = dynamodb.Table(projects_table_name)
    subscriptions_table = dynamodb.Table(subscriptions_table_name)
    password_reset_tokens_table = dynamodb.Table(password_reset_tokens_table_name)
    audit_logs_table = dynamodb.Table(audit_logs_table_name)
    
    # Extract HTTP method and path
    http_method = event.get('httpMethod', 'GET')
    path = event.get('path', '/')
    path_parameters = event.get('pathParameters') or {}
    
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
        elif path == '/auth/password-reset':
            if http_method == 'POST':
                # Determine operation based on request body
                body = json.loads(event.get('body', '{}'))
                operation = body.get('operation', 'initiate')
                
                if operation == 'initiate':
                    return initiate_password_reset(people_table, password_reset_tokens_table, audit_logs_table, event)
                elif operation == 'complete':
                    return reset_password_with_token(people_table, password_reset_tokens_table, audit_logs_table, event)
                else:
                    return error_response(400, 'Invalid operation')
            
            elif http_method == 'GET':
                # Token validation via query parameters
                query_params = event.get('queryStringParameters') or {}
                token = query_params.get('token')
                if token:
                    return validate_reset_token(password_reset_tokens_table, token)
                else:
                    return error_response(400, 'Token parameter is required')
        
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
        
        # Default response for unmatched routes
        return error_response(404, 'Route not found')
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return error_response(500, 'Internal server error')

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
