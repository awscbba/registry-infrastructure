#!/usr/bin/env python3
"""
Authentication Lambda Handler
Handles login, logout, profile, and authentication-related operations
"""
import json
import boto3
import bcrypt
import jwt
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
import os

# Environment variables
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production')
JWT_EXPIRATION_HOURS = int(os.environ.get('JWT_EXPIRATION_HOURS', '24'))

# Initialize DynamoDB
dynamodb = boto3.resource('dynamodb')

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)

def get_cors_headers():
    """Get CORS headers for API responses"""
    return {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'
    }

def error_response(status_code, message):
    """Return standardized error response"""
    return {
        'statusCode': status_code,
        'headers': get_cors_headers(),
        'body': json.dumps({'error': message}, cls=DecimalEncoder)
    }

def success_response(data, status_code=200):
    """Return standardized success response"""
    return {
        'statusCode': status_code,
        'headers': get_cors_headers(),
        'body': json.dumps(data, cls=DecimalEncoder)
    }

def hash_password(password):
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

def generate_jwt_token(user_data):
    """Generate JWT token for user"""
    payload = {
        'sub': user_data['id'],
        'email': user_data['email'],
        'firstName': user_data.get('firstName', ''),
        'lastName': user_data.get('lastName', ''),
        'isAdmin': user_data.get('isAdmin', False),
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_jwt_token(token):
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_person_by_email(people_table, email):
    """Get person by email from database"""
    try:
        response = people_table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('email').eq(email.lower())
        )
        items = response.get('Items', [])
        return items[0] if items else None
    except Exception as e:
        print(f"Error getting person by email: {str(e)}")
        return None

def get_client_ip(event):
    """Extract client IP from event"""
    headers = event.get('headers', {})
    
    # Check various headers for client IP
    forwarded_for = headers.get('X-Forwarded-For') or headers.get('x-forwarded-for')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    
    real_ip = headers.get('X-Real-IP') or headers.get('x-real-ip')
    if real_ip:
        return real_ip
    
    # Fallback to source IP
    return event.get('requestContext', {}).get('identity', {}).get('sourceIp', 'unknown')

def get_user_agent(event):
    """Extract user agent from event"""
    headers = event.get('headers', {})
    return headers.get('User-Agent', headers.get('user-agent', 'unknown'))

def create_audit_log(audit_logs_table, person_id, action, success, details=None, ip_address=None, user_agent=None):
    """Create audit log entry"""
    try:
        log_entry = {
            'id': str(uuid.uuid4()),
            'personId': person_id,
            'action': action,
            'success': success,
            'timestamp': datetime.utcnow().isoformat(),
            'ipAddress': ip_address or 'unknown',
            'userAgent': user_agent or 'unknown',
            'details': details or {}
        }
        
        audit_logs_table.put_item(Item=log_entry)
        return True
    except Exception as e:
        print(f"Error creating audit log: {str(e)}")
        return False

def handle_login(event, people_table, audit_logs_table):
    """Handle user login"""
    try:
        body = json.loads(event.get('body', '{}'))
        email = body.get('email', '').strip().lower()
        password = body.get('password', '')
        
        if not email or not password:
            return error_response(400, 'Email and password are required')
        
        # Get client information
        client_ip = get_client_ip(event)
        user_agent = get_user_agent(event)
        
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
        
        # Check if user has a password set
        if not person.get('password'):
            return error_response(401, 'Account not set up for login. Please contact administrator.')
        
        # Verify password
        if not verify_password(password, person['password']):
            # Log failed login attempt
            create_audit_log(
                audit_logs_table,
                person['id'],
                'LOGIN_FAILED',
                False,
                {'email': email, 'reason': 'invalid_password'},
                client_ip,
                user_agent
            )
            return error_response(401, 'Invalid email or password')
        
        # Generate JWT token
        token = generate_jwt_token(person)
        
        # Log successful login
        create_audit_log(
            audit_logs_table,
            person['id'],
            'LOGIN_SUCCESS',
            True,
            {'email': email},
            client_ip,
            user_agent
        )
        
        # Return success response
        return success_response({
            'success': True,
            'message': 'Login successful',
            'accessToken': token,
            'expiresAt': (datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)).isoformat(),
            'user': {
                'id': person['id'],
                'email': person['email'],
                'firstName': person.get('firstName', ''),
                'lastName': person.get('lastName', ''),
                'isAdmin': person.get('isAdmin', False)
            }
        })
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        return error_response(500, 'Internal server error during login')

def handle_logout(event):
    """Handle user logout"""
    try:
        # For JWT-based authentication, logout is typically handled client-side
        # by removing the token from storage
        return success_response({
            'success': True,
            'message': 'Logout successful'
        })
        
    except Exception as e:
        print(f"Logout error: {str(e)}")
        return error_response(500, 'Internal server error during logout')

def handle_profile(event, people_table):
    """Get current user profile from JWT token"""
    try:
        # Extract token from Authorization header
        headers = event.get('headers', {})
        auth_header = headers.get('Authorization') or headers.get('authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return error_response(401, 'Missing or invalid authorization header')
        
        token = auth_header.replace('Bearer ', '')
        
        # Verify and decode JWT token
        payload = verify_jwt_token(token)
        if not payload:
            return error_response(401, 'Invalid or expired token')
        
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
            'phone': person.get('phone', ''),
            'dateOfBirth': person.get('dateOfBirth', ''),
            'address': person.get('address', {}),
            'createdAt': person.get('createdAt', ''),
            'updatedAt': person.get('updatedAt', ''),
            'isAdmin': person.get('isAdmin', False)
        }
        
        return success_response({
            'success': True,
            'user': user_profile
        })
        
    except Exception as e:
        print(f"Get profile error: {str(e)}")
        return error_response(500, 'Internal server error')

def lambda_handler(event, context):
    """Main Lambda handler for authentication operations"""
    try:
        # Get tables
        people_table = dynamodb.Table(os.environ.get('PEOPLE_TABLE_NAME', 'PeopleTable'))
        audit_logs_table = dynamodb.Table(os.environ.get('AUDIT_LOGS_TABLE_NAME', 'AuditLogsTable'))
        
        # Get HTTP method and path
        http_method = event.get('httpMethod', 'GET')
        path = event.get('path', '/')
        
        print(f"🔐 Auth Handler - Processing: {http_method} {path}")
        
        # Handle CORS preflight requests
        if http_method == 'OPTIONS':
            return {
                'statusCode': 200,
                'headers': get_cors_headers(),
                'body': json.dumps({'message': 'CORS preflight successful'})
            }
        
        # Route to appropriate handler
        if path == '/auth/login' and http_method == 'POST':
            return handle_login(event, people_table, audit_logs_table)
        elif path == '/auth/logout' and http_method == 'POST':
            return handle_logout(event)
        elif path == '/auth/me' and http_method == 'GET':
            return handle_profile(event, people_table)
        else:
            return error_response(404, f'Endpoint not found: {http_method} {path}')
            
    except Exception as e:
        print(f"Auth handler error: {str(e)}")
        return error_response(500, 'Internal server error')
