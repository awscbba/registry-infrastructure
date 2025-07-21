"""
CSRF Protection Service for Password Forms
Implements token-based CSRF protection with secure token generation and validation
"""

import json
import boto3
import os
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import base64


class CSRFProtection:
    """
    CSRF Protection implementation using secure tokens and DynamoDB storage
    """
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.csrf_table_name = os.environ.get('CSRF_TOKEN_TABLE_NAME', 'CSRFTokenTable')
        
        # Get CSRF secret from environment or generate a default one
        self.csrf_secret = os.environ.get('CSRF_SECRET', 'default-csrf-secret-change-in-production')
        
        try:
            self.csrf_table = self.dynamodb.Table(self.csrf_table_name)
        except Exception:
            # Table might not exist yet
            self.csrf_table = None
    
    def generate_csrf_token(self, session_id: str, form_type: str = 'password_form') -> str:
        """
        Generate a secure CSRF token for a specific session and form type
        """
        # Generate a random token
        random_token = secrets.token_urlsafe(32)
        
        # Create timestamp
        timestamp = datetime.utcnow().isoformat()
        
        # Create the token payload
        token_data = {
            'session_id': session_id,
            'form_type': form_type,
            'timestamp': timestamp,
            'random': random_token
        }
        
        # Create HMAC signature
        token_string = json.dumps(token_data, sort_keys=True)
        signature = hmac.new(
            self.csrf_secret.encode(),
            token_string.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Combine token data and signature
        csrf_token = base64.b64encode(
            json.dumps({
                'data': token_data,
                'signature': signature
            }).encode()
        ).decode()
        
        # Store token in DynamoDB if available
        if self.csrf_table:
            try:
                self.csrf_table.put_item(
                    Item={
                        'token': csrf_token,
                        'session_id': session_id,
                        'form_type': form_type,
                        'created_at': timestamp,
                        'expires_at': (datetime.utcnow() + timedelta(hours=1)).isoformat(),
                        'used': False,
                        'ttl': int((datetime.utcnow() + timedelta(hours=2)).timestamp())
                    }
                )
            except Exception as e:
                print(f"⚠️ Failed to store CSRF token: {str(e)}")
        
        return csrf_token
    
    def validate_csrf_token(self, token: str, session_id: str, form_type: str = 'password_form') -> Tuple[bool, str]:
        """
        Validate a CSRF token
        Returns (is_valid, error_message)
        """
        if not token:
            return False, "CSRF token is required"
        
        try:
            # Decode the token
            token_json = base64.b64decode(token.encode()).decode()
            token_obj = json.loads(token_json)
            
            token_data = token_obj['data']
            provided_signature = token_obj['signature']
            
            # Verify signature
            token_string = json.dumps(token_data, sort_keys=True)
            expected_signature = hmac.new(
                self.csrf_secret.encode(),
                token_string.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(provided_signature, expected_signature):
                return False, "Invalid CSRF token signature"
            
            # Check session ID
            if token_data['session_id'] != session_id:
                return False, "CSRF token session mismatch"
            
            # Check form type
            if token_data['form_type'] != form_type:
                return False, "CSRF token form type mismatch"
            
            # Check expiration (1 hour)
            token_time = datetime.fromisoformat(token_data['timestamp'])
            if datetime.utcnow() - token_time > timedelta(hours=1):
                return False, "CSRF token has expired"
            
            # Check if token was already used (if DynamoDB is available)
            if self.csrf_table:
                try:
                    response = self.csrf_table.get_item(Key={'token': token})
                    if 'Item' in response:
                        if response['Item']['used']:
                            return False, "CSRF token has already been used"
                        
                        # Mark token as used
                        self.csrf_table.update_item(
                            Key={'token': token},
                            UpdateExpression='SET used = :used',
                            ExpressionAttributeValues={':used': True}
                        )
                except Exception as e:
                    print(f"⚠️ Failed to check CSRF token usage: {str(e)}")
                    # Continue validation even if DynamoDB check fails
            
            return True, "Valid CSRF token"
            
        except Exception as e:
            return False, f"Invalid CSRF token format: {str(e)}"
    
    def get_session_id(self, event: Dict) -> str:
        """
        Extract or generate a session ID from the request
        """
        # Try to get session ID from JWT token
        auth_header = event.get('headers', {}).get('Authorization', '')
        if auth_header.startswith('Bearer '):
            try:
                import jwt
                token = auth_header.split(' ')[1]
                decoded = jwt.decode(token, options={"verify_signature": False})
                if 'sub' in decoded:
                    return decoded['sub']
            except Exception:
                pass
        
        # Fallback to IP + User-Agent hash
        ip_address = (
            event.get('requestContext', {}).get('identity', {}).get('sourceIp') or
            event.get('headers', {}).get('X-Forwarded-For', '').split(',')[0].strip() or
            'unknown'
        )
        user_agent = event.get('headers', {}).get('User-Agent', 'unknown')
        
        session_data = f"{ip_address}:{user_agent}"
        return hashlib.sha256(session_data.encode()).hexdigest()[:16]
    
    def add_csrf_headers(self, response: Dict, session_id: str, form_type: str = 'password_form') -> Dict:
        """
        Add CSRF token to response headers
        """
        csrf_token = self.generate_csrf_token(session_id, form_type)
        
        if 'headers' not in response:
            response['headers'] = {}
        
        response['headers']['X-CSRF-Token'] = csrf_token
        
        return response


def csrf_protect(form_type: str = 'password_form'):
    """
    Decorator to protect endpoints with CSRF validation
    """
    def decorator(func):
        def wrapper(event, *args, **kwargs):
            csrf_protection = CSRFProtection()
            
            # Skip CSRF protection for GET requests
            http_method = event.get('httpMethod', '').upper()
            if http_method == 'GET':
                # Generate and include CSRF token in response
                session_id = csrf_protection.get_session_id(event)
                result = func(event, *args, **kwargs)
                
                if isinstance(result, dict):
                    result = csrf_protection.add_csrf_headers(result, session_id, form_type)
                
                return result
            
            # For POST/PUT/DELETE requests, validate CSRF token
            if http_method in ['POST', 'PUT', 'DELETE']:
                session_id = csrf_protection.get_session_id(event)
                
                # Get CSRF token from header or body
                csrf_token = event.get('headers', {}).get('X-CSRF-Token')
                
                if not csrf_token:
                    # Try to get from request body
                    try:
                        if event.get('body'):
                            body = json.loads(event['body'])
                            csrf_token = body.get('csrf_token')
                    except json.JSONDecodeError:
                        pass
                
                # Validate CSRF token
                is_valid, error_message = csrf_protection.validate_csrf_token(csrf_token, session_id, form_type)
                
                if not is_valid:
                    return {
                        'statusCode': 403,
                        'headers': {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*',
                            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-CSRF-Token',
                            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
                        },
                        'body': json.dumps({
                            'error': 'CSRF validation failed',
                            'message': error_message
                        })
                    }
            
            # Execute the original function
            result = func(event, *args, **kwargs)
            
            # Add CSRF token to response for future requests
            if isinstance(result, dict) and result.get('statusCode', 200) < 400:
                session_id = csrf_protection.get_session_id(event)
                result = csrf_protection.add_csrf_headers(result, session_id, form_type)
            
            return result
        
        return wrapper
    return decorator


# Utility functions for manual CSRF protection
def generate_csrf_token_for_session(session_id: str, form_type: str = 'password_form') -> str:
    """
    Generate a CSRF token for a specific session
    """
    csrf_protection = CSRFProtection()
    return csrf_protection.generate_csrf_token(session_id, form_type)


def validate_csrf_token_for_session(token: str, session_id: str, form_type: str = 'password_form') -> Tuple[bool, str]:
    """
    Validate a CSRF token for a specific session
    """
    csrf_protection = CSRFProtection()
    return csrf_protection.validate_csrf_token(token, session_id, form_type)
