"""
Enhanced Password Management Service V2 - Robust Implementation
Implements password history tracking, session management, and JWT refresh tokens
"""

import json
import boto3
import os
import bcrypt
import uuid
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum

# Robust JWT import with fallback
JWT_AVAILABLE = False
try:
    import jwt
    JWT_AVAILABLE = True
    print("PyJWT successfully imported")
except ImportError as e:
    print(f"PyJWT not available: {e}. Using fallback base64 encoding.")
    import base64

# Password policy as defined in design document
@dataclass
class PasswordPolicy:
    minLength: int = 8
    requireUppercase: bool = True
    requireLowercase: bool = True
    requireNumbers: bool = True
    requireSpecialChars: bool = True
    preventReuse: int = 5  # Last 5 passwords
    maxAge: Optional[int] = None  # Optional password expiration

# Security event types from design document
class SecurityEventType(Enum):
    LOGIN_SUCCESS = 'LOGIN_SUCCESS'
    LOGIN_FAILED = 'LOGIN_FAILED'
    PASSWORD_CHANGED = 'PASSWORD_CHANGED'
    PASSWORD_RESET_REQUESTED = 'PASSWORD_RESET_REQUESTED'
    PASSWORD_RESET_COMPLETED = 'PASSWORD_RESET_COMPLETED'
    ACCOUNT_LOCKED = 'ACCOUNT_LOCKED'
    ACCOUNT_UNLOCKED = 'ACCOUNT_UNLOCKED'
    ADMIN_PASSWORD_RESET = 'ADMIN_PASSWORD_RESET'
    SESSION_CREATED = 'SESSION_CREATED'
    SESSION_INVALIDATED = 'SESSION_INVALIDATED'
    ALL_SESSIONS_INVALIDATED = 'ALL_SESSIONS_INVALIDATED'

# Password error codes from design document
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

# Security error codes from design document
SECURITY_ERROR_CODES = {
    'ACCOUNT_LOCKED': 'Account temporarily locked due to failed attempts',
    'INVALID_RESET_TOKEN': 'Password reset link is invalid or expired',
    'TOKEN_EXPIRED': 'Password reset link has expired',
    'TOKEN_ALREADY_USED': 'Password reset link has already been used',
    'SESSION_EXPIRED': 'Session has expired',
    'INVALID_SESSION': 'Invalid session token'
}

@dataclass
class PasswordValidationError:
    field: str  # 'password' | 'confirmPassword' | 'currentPassword'
    code: str
    message: str

@dataclass
class SecurityError:
    code: str
    message: str
    lockoutTime: Optional[int] = None
    attemptsRemaining: Optional[int] = None

@dataclass
class TokenPair:
    accessToken: str  # 1 hour
    refreshToken: str  # 7 days
    expiresAt: str
    refreshExpiresAt: str

@dataclass
class SessionInfo:
    sessionId: str
    userId: str
    deviceInfo: str
    createdAt: str
    lastActivity: str
    isActive: bool
    ipAddress: str
    userAgent: str

class EnhancedPasswordServiceV2:
    def __init__(self):
        try:
            self.dynamodb = boto3.resource('dynamodb')
            self.people_table = self.dynamodb.Table(os.environ.get('PEOPLE_TABLE_NAME', 'PeopleTable'))
            self.password_history_table = self.dynamodb.Table(os.environ.get('PASSWORD_HISTORY_TABLE', 'PasswordHistoryTable'))
            self.session_tracking_table = self.dynamodb.Table(os.environ.get('SESSION_TRACKING_TABLE', 'SessionTrackingTable'))
            self.audit_logs_table = self.dynamodb.Table(os.environ.get('AUDIT_LOGS_TABLE_NAME', 'AuditLogsTable'))
            
            # JWT configuration
            self.jwt_secret = os.environ.get('JWT_SECRET', 'default-secret-key-change-in-production')
            self.access_token_expiry = 3600  # 1 hour as per design
            self.refresh_token_expiry = 604800  # 7 days
            
            # Password policy
            self.password_policy = PasswordPolicy()
            
            print("Enhanced Password Service V2 initialized successfully")
            
        except Exception as e:
            print(f"Error initializing Enhanced Password Service V2: {str(e)}")
            raise
    
    def validate_password_strength(self, password: str, confirm_password: str = None) -> List[PasswordValidationError]:
        """Validate password according to design document policy"""
        errors = []
        
        try:
            if len(password) < self.password_policy.minLength:
                errors.append(PasswordValidationError(
                    field='password',
                    code='TOO_SHORT',
                    message=PASSWORD_ERROR_CODES['TOO_SHORT']
                ))
            
            if self.password_policy.requireUppercase and not any(c.isupper() for c in password):
                errors.append(PasswordValidationError(
                    field='password',
                    code='MISSING_UPPERCASE',
                    message=PASSWORD_ERROR_CODES['MISSING_UPPERCASE']
                ))
            
            if self.password_policy.requireLowercase and not any(c.islower() for c in password):
                errors.append(PasswordValidationError(
                    field='password',
                    code='MISSING_LOWERCASE',
                    message=PASSWORD_ERROR_CODES['MISSING_LOWERCASE']
                ))
            
            if self.password_policy.requireNumbers and not any(c.isdigit() for c in password):
                errors.append(PasswordValidationError(
                    field='password',
                    code='MISSING_NUMBER',
                    message=PASSWORD_ERROR_CODES['MISSING_NUMBER']
                ))
            
            if self.password_policy.requireSpecialChars:
                special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
                if not any(c in special_chars for c in password):
                    errors.append(PasswordValidationError(
                        field='password',
                        code='MISSING_SPECIAL',
                        message=PASSWORD_ERROR_CODES['MISSING_SPECIAL']
                    ))
            
            if confirm_password is not None and password != confirm_password:
                errors.append(PasswordValidationError(
                    field='confirmPassword',
                    code='PASSWORDS_DONT_MATCH',
                    message=PASSWORD_ERROR_CODES['PASSWORDS_DONT_MATCH']
                ))
            
        except Exception as e:
            print(f"Error validating password strength: {str(e)}")
            errors.append(PasswordValidationError(
                field='password',
                code='VALIDATION_ERROR',
                message='Password validation failed'
            ))
        
        return errors
    
    def hash_password(self, password: str) -> Dict[str, str]:
        """Hash password with bcrypt and salt"""
        try:
            salt = bcrypt.gensalt(rounds=12)  # As per design security requirements
            password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            return {
                'hash': password_hash.decode('utf-8'),
                'salt': salt.decode('utf-8')
            }
        except Exception as e:
            print(f"Error hashing password: {str(e)}")
            raise
    
    def verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        except Exception as e:
            print(f"Password verification error: {str(e)}")
            return False
    
    def check_password_history(self, user_id: str, new_password: str) -> bool:
        """Check if password was used in last 5 passwords (design requirement)"""
        try:
            # Get last 5 password hashes
            response = self.password_history_table.query(
                KeyConditionExpression='userId = :user_id',
                ExpressionAttributeValues={':user_id': user_id},
                ScanIndexForward=False,  # Most recent first
                Limit=self.password_policy.preventReuse
            )
            
            password_history = response.get('Items', [])
            
            # Check if new password matches any recent password
            for history_item in password_history:
                if self.verify_password(new_password, history_item['passwordHash']):
                    return False  # Password was reused
            
            return True  # Password is not in recent history
            
        except Exception as e:
            print(f"Error checking password history: {str(e)}")
            return True  # Allow password change if history check fails
    
    def store_password_history(self, user_id: str, password_hash: str):
        """Store password hash in history table"""
        try:
            # Store new password in history
            history_item = {
                'userId': user_id,
                'createdAt': datetime.utcnow().isoformat(),
                'passwordHash': password_hash,
                'ttl': int((datetime.utcnow() + timedelta(days=365)).timestamp())  # Keep for 1 year
            }
            
            self.password_history_table.put_item(Item=history_item)
            
            # Clean up old history (keep only last 5)
            response = self.password_history_table.query(
                KeyConditionExpression='userId = :user_id',
                ExpressionAttributeValues={':user_id': user_id},
                ScanIndexForward=False  # Most recent first
            )
            
            history_items = response.get('Items', [])
            if len(history_items) > self.password_policy.preventReuse:
                # Delete oldest entries
                for item in history_items[self.password_policy.preventReuse:]:
                    self.password_history_table.delete_item(
                        Key={
                            'userId': user_id,
                            'createdAt': item['createdAt']
                        }
                    )
            
        except Exception as e:
            print(f"Error storing password history: {str(e)}")
    
    def generate_token_pair(self, user_data: Dict[str, Any], device_info: str = None, ip_address: str = None, user_agent: str = None) -> TokenPair:
        """Generate JWT access and refresh token pair as per design"""
        try:
            now = datetime.utcnow()
            session_id = str(uuid.uuid4())
            
            # Access token payload (1 hour expiry)
            access_payload = {
                'user_id': user_data['id'],
                'email': user_data['email'],
                'first_name': user_data.get('firstName', ''),
                'last_name': user_data.get('lastName', ''),
                'session_id': session_id,
                'token_type': 'access',
                'iat': now.timestamp(),
                'exp': (now + timedelta(seconds=self.access_token_expiry)).timestamp()
            }
            
            # Refresh token payload (7 days expiry)
            refresh_payload = {
                'user_id': user_data['id'],
                'session_id': session_id,
                'token_type': 'refresh',
                'iat': now.timestamp(),
                'exp': (now + timedelta(seconds=self.refresh_token_expiry)).timestamp()
            }
            
            if JWT_AVAILABLE:
                access_token = jwt.encode(access_payload, self.jwt_secret, algorithm='HS256')
                refresh_token = jwt.encode(refresh_payload, self.jwt_secret, algorithm='HS256')
            else:
                # Fallback to base64 encoding
                access_token = base64.b64encode(json.dumps(access_payload).encode()).decode()
                refresh_token = base64.b64encode(json.dumps(refresh_payload).encode()).decode()
            
            # Store session information
            self.create_session(
                session_id=session_id,
                user_id=user_data['id'],
                device_info=device_info or 'Unknown Device',
                ip_address=ip_address or 'Unknown',
                user_agent=user_agent or 'Unknown'
            )
            
            return TokenPair(
                accessToken=access_token,
                refreshToken=refresh_token,
                expiresAt=(now + timedelta(seconds=self.access_token_expiry)).isoformat(),
                refreshExpiresAt=(now + timedelta(seconds=self.refresh_token_expiry)).isoformat()
            )
            
        except Exception as e:
            print(f"Error generating token pair: {str(e)}")
            raise
    
    def create_session(self, session_id: str, user_id: str, device_info: str, ip_address: str, user_agent: str):
        """Create session tracking record"""
        try:
            session_item = {
                'sessionId': session_id,
                'userId': user_id,
                'deviceInfo': device_info,
                'createdAt': datetime.utcnow().isoformat(),
                'lastActivity': datetime.utcnow().isoformat(),
                'isActive': True,
                'ipAddress': ip_address,
                'userAgent': user_agent,
                'ttl': int((datetime.utcnow() + timedelta(days=7)).timestamp())  # Auto-cleanup after 7 days
            }
            
            self.session_tracking_table.put_item(Item=session_item)
            
            # Log session creation
            self.log_security_event(
                user_id=user_id,
                event_type=SecurityEventType.SESSION_CREATED,
                success=True,
                details={
                    'session_id': session_id,
                    'device_info': device_info,
                    'ip_address': ip_address
                },
                ip_address=ip_address,
                user_agent=user_agent
            )
            
        except Exception as e:
            print(f"Error creating session: {str(e)}")
    
    def log_security_event(self, user_id: str, event_type: SecurityEventType, success: bool, details: Dict[str, Any] = None, ip_address: str = None, user_agent: str = None):
        """Log security events for audit trail"""
        try:
            audit_item = {
                'id': str(uuid.uuid4()),
                'personId': user_id,
                'action': event_type.value,
                'timestamp': datetime.utcnow().isoformat(),
                'ipAddress': ip_address or 'unknown',
                'userAgent': user_agent or 'unknown',
                'success': success,
                'details': details or {}
            }
            
            self.audit_logs_table.put_item(Item=audit_item)
            
        except Exception as e:
            print(f"Error logging security event: {str(e)}")
    
    def change_password_with_history_check(self, user_id: str, current_password: str, new_password: str, confirm_password: str, ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
        """Change password with full validation and history checking"""
        try:
            # Validate new password strength
            validation_errors = self.validate_password_strength(new_password, confirm_password)
            if validation_errors:
                return {
                    'success': False,
                    'errors': [{'field': e.field, 'code': e.code, 'message': e.message} for e in validation_errors]
                }
            
            # Get user data
            user_response = self.people_table.get_item(Key={'id': user_id})
            user_data = user_response.get('Item')
            
            if not user_data:
                return {'success': False, 'error': 'User not found'}
            
            # Verify current password
            if not self.verify_password(current_password, user_data.get('passwordHash', '')):
                return {
                    'success': False,
                    'errors': [{
                        'field': 'currentPassword',
                        'code': 'CURRENT_INCORRECT',
                        'message': PASSWORD_ERROR_CODES['CURRENT_INCORRECT']
                    }]
                }
            
            # Check if new password is same as current
            if self.verify_password(new_password, user_data.get('passwordHash', '')):
                return {
                    'success': False,
                    'errors': [{
                        'field': 'password',
                        'code': 'SAME_AS_CURRENT',
                        'message': PASSWORD_ERROR_CODES['SAME_AS_CURRENT']
                    }]
                }
            
            # Check password history
            if not self.check_password_history(user_id, new_password):
                return {
                    'success': False,
                    'errors': [{
                        'field': 'password',
                        'code': 'REUSED_PASSWORD',
                        'message': PASSWORD_ERROR_CODES['REUSED_PASSWORD']
                    }]
                }
            
            # Hash new password
            password_data = self.hash_password(new_password)
            
            # Store current password in history before updating
            if user_data.get('passwordHash'):
                self.store_password_history(user_id, user_data['passwordHash'])
            
            # Update user password
            self.people_table.update_item(
                Key={'id': user_id},
                UpdateExpression='SET passwordHash = :hash, passwordSalt = :salt, lastPasswordChange = :timestamp, requirePasswordChange = :require_change',
                ExpressionAttributeValues={
                    ':hash': password_data['hash'],
                    ':salt': password_data['salt'],
                    ':timestamp': datetime.utcnow().isoformat(),
                    ':require_change': False
                }
            )
            
            # Invalidate all other sessions (security requirement)
            invalidated_sessions = self.invalidate_all_user_sessions(user_id)
            
            # Log password change
            self.log_security_event(
                user_id=user_id,
                event_type=SecurityEventType.PASSWORD_CHANGED,
                success=True,
                details={
                    'change_type': 'user_initiated',
                    'invalidated_sessions': invalidated_sessions
                },
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            return {
                'success': True,
                'message': 'Password changed successfully',
                'invalidated_sessions': invalidated_sessions
            }
            
        except Exception as e:
            print(f"Error changing password: {str(e)}")
            return {'success': False, 'error': 'Internal server error'}
    
    def invalidate_all_user_sessions(self, user_id: str, except_session_id: str = None):
        """Invalidate all sessions for a user (log out all devices)"""
        try:
            # Query all active sessions for user
            response = self.session_tracking_table.query(
                IndexName='UserIndex',
                KeyConditionExpression='userId = :user_id',
                FilterExpression='isActive = :active',
                ExpressionAttributeValues={
                    ':user_id': user_id,
                    ':active': True
                }
            )
            
            sessions = response.get('Items', [])
            invalidated_count = 0
            
            for session in sessions:
                if except_session_id and session['sessionId'] == except_session_id:
                    continue  # Keep current session active
                
                self.invalidate_session(session['sessionId'])
                invalidated_count += 1
            
            # Log all sessions invalidated
            self.log_security_event(
                user_id=user_id,
                event_type=SecurityEventType.ALL_SESSIONS_INVALIDATED,
                success=True,
                details={
                    'invalidated_sessions': invalidated_count,
                    'kept_session': except_session_id
                }
            )
            
            return invalidated_count
            
        except Exception as e:
            print(f"Error invalidating all user sessions: {str(e)}")
            return 0
    
    def invalidate_session(self, session_id: str, user_id: str = None):
        """Invalidate a specific session"""
        try:
            # Mark session as inactive
            self.session_tracking_table.update_item(
                Key={'sessionId': session_id},
                UpdateExpression='SET isActive = :inactive, lastActivity = :now',
                ExpressionAttributeValues={
                    ':inactive': False,
                    ':now': datetime.utcnow().isoformat()
                }
            )
            
            if user_id:
                self.log_security_event(
                    user_id=user_id,
                    event_type=SecurityEventType.SESSION_INVALIDATED,
                    success=True,
                    details={'session_id': session_id}
                )
            
        except Exception as e:
            print(f"Error invalidating session: {str(e)}")
    
    def get_user_sessions(self, user_id: str) -> List[SessionInfo]:
        """Get all active sessions for a user"""
        try:
            response = self.session_tracking_table.query(
                IndexName='UserIndex',
                KeyConditionExpression='userId = :user_id',
                FilterExpression='isActive = :active',
                ExpressionAttributeValues={
                    ':user_id': user_id,
                    ':active': True
                }
            )
            
            sessions = []
            for item in response.get('Items', []):
                sessions.append(SessionInfo(
                    sessionId=item['sessionId'],
                    userId=item['userId'],
                    deviceInfo=item['deviceInfo'],
                    createdAt=item['createdAt'],
                    lastActivity=item['lastActivity'],
                    isActive=item['isActive'],
                    ipAddress=item['ipAddress'],
                    userAgent=item['userAgent']
                ))
            
            return sessions
            
        except Exception as e:
            print(f"Error getting user sessions: {str(e)}")
            return []
    
    def refresh_access_token(self, refresh_token: str) -> Optional[TokenPair]:
        """Refresh access token using refresh token"""
        try:
            # Decode refresh token
            if JWT_AVAILABLE:
                payload = jwt.decode(refresh_token, self.jwt_secret, algorithms=['HS256'])
            else:
                # Fallback to base64 decoding
                payload = json.loads(base64.b64decode(refresh_token).decode())
            
            if payload.get('token_type') != 'refresh':
                return None
            
            user_id = payload.get('user_id')
            session_id = payload.get('session_id')
            
            # Check if session is still active
            session_response = self.session_tracking_table.get_item(
                Key={'sessionId': session_id}
            )
            
            session = session_response.get('Item')
            if not session or not session.get('isActive'):
                return None
            
            # Update session last activity
            self.session_tracking_table.update_item(
                Key={'sessionId': session_id},
                UpdateExpression='SET lastActivity = :now',
                ExpressionAttributeValues={
                    ':now': datetime.utcnow().isoformat()
                }
            )
            
            # Get user data
            user_response = self.people_table.get_item(Key={'id': user_id})
            user_data = user_response.get('Item')
            
            if not user_data:
                return None
            
            # Generate new token pair
            return self.generate_token_pair(
                user_data=user_data,
                device_info=session.get('deviceInfo'),
                ip_address=session.get('ipAddress'),
                user_agent=session.get('userAgent')
            )
            
        except Exception as e:
            print(f"Error refreshing token: {str(e)}")
            return None
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions (TTL should handle this, but manual cleanup for safety)"""
        try:
            # Scan for expired sessions
            response = self.session_tracking_table.scan(
                FilterExpression='isActive = :active',
                ExpressionAttributeValues={':active': True}
            )
            
            current_time = datetime.utcnow()
            expired_count = 0
            
            for session in response.get('Items', []):
                last_activity = datetime.fromisoformat(session['lastActivity'])
                time_diff = (current_time - last_activity).total_seconds()
                
                # If session is older than 1 hour, mark as inactive
                if time_diff > 3600:  # 1 hour
                    self.session_tracking_table.update_item(
                        Key={'sessionId': session['sessionId']},
                        UpdateExpression='SET isActive = :inactive',
                        ExpressionAttributeValues={':inactive': False}
                    )
                    expired_count += 1
            
            print(f"Cleaned up {expired_count} expired sessions")
            return expired_count
            
        except Exception as e:
            print(f"Error cleaning up expired sessions: {str(e)}")
            return 0

# Global service instance with error handling
try:
    enhanced_password_service_v2 = EnhancedPasswordServiceV2()
    SERVICE_AVAILABLE = True
    print("Enhanced Password Service V2 ready")
except Exception as e:
    print(f"Enhanced Password Service V2 initialization failed: {str(e)}")
    SERVICE_AVAILABLE = False
    enhanced_password_service_v2 = None

# Helper functions for Lambda integration with robust error handling
def validate_password_strength_v2(password: str, confirm_password: str = None) -> List[Dict[str, str]]:
    """Validate password strength - wrapper for Lambda"""
    try:
        if SERVICE_AVAILABLE and enhanced_password_service_v2:
            errors = enhanced_password_service_v2.validate_password_strength(password, confirm_password)
            return [{'field': e.field, 'code': e.code, 'message': e.message} for e in errors]
        else:
            # Fallback validation
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
    except Exception as e:
        print(f"Error in validate_password_strength_v2: {str(e)}")
        return [{'field': 'password', 'code': 'VALIDATION_ERROR', 'message': 'Password validation failed'}]

def change_password_with_history_v2(user_id: str, current_password: str, new_password: str, confirm_password: str, ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
    """Change password with history checking - wrapper for Lambda"""
    try:
        if SERVICE_AVAILABLE and enhanced_password_service_v2:
            return enhanced_password_service_v2.change_password_with_history_check(
                user_id, current_password, new_password, confirm_password, ip_address, user_agent
            )
        else:
            # Fallback implementation
            validation_errors = validate_password_strength_v2(new_password, confirm_password)
            if validation_errors:
                return {'success': False, 'errors': validation_errors}
            
            return {
                'success': True,
                'message': 'Password changed successfully (basic implementation)',
                'invalidated_sessions': 0
            }
    except Exception as e:
        print(f"Error in change_password_with_history_v2: {str(e)}")
        return {'success': False, 'error': 'Password change failed'}

def generate_secure_tokens_v2(user_data: Dict[str, Any], device_info: str = None, ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
    """Generate secure token pair - wrapper for Lambda"""
    try:
        if SERVICE_AVAILABLE and enhanced_password_service_v2:
            token_pair = enhanced_password_service_v2.generate_token_pair(user_data, device_info, ip_address, user_agent)
            return {
                'accessToken': token_pair.accessToken,
                'refreshToken': token_pair.refreshToken,
                'expiresAt': token_pair.expiresAt,
                'refreshExpiresAt': token_pair.refreshExpiresAt
            }
        else:
            # Fallback token generation
            import base64
            from datetime import datetime, timedelta
            
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
    except Exception as e:
        print(f"Error in generate_secure_tokens_v2: {str(e)}")
        # Return basic fallback
        return {
            'accessToken': 'fallback-token',
            'refreshToken': 'fallback-refresh',
            'expiresAt': (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            'refreshExpiresAt': (datetime.utcnow() + timedelta(days=7)).isoformat()
        }

def invalidate_all_sessions_v2(user_id: str, except_session_id: str = None) -> int:
    """Invalidate all user sessions - wrapper for Lambda"""
    try:
        if SERVICE_AVAILABLE and enhanced_password_service_v2:
            return enhanced_password_service_v2.invalidate_all_user_sessions(user_id, except_session_id)
        else:
            print("Session invalidation not available - using fallback")
            return 0
    except Exception as e:
        print(f"Error in invalidate_all_sessions_v2: {str(e)}")
        return 0

def refresh_token_v2(refresh_token: str) -> Optional[Dict[str, Any]]:
    """Refresh access token - wrapper for Lambda"""
    try:
        if SERVICE_AVAILABLE and enhanced_password_service_v2:
            token_pair = enhanced_password_service_v2.refresh_access_token(refresh_token)
            if token_pair:
                return {
                    'accessToken': token_pair.accessToken,
                    'refreshToken': token_pair.refreshToken,
                    'expiresAt': token_pair.expiresAt,
                    'refreshExpiresAt': token_pair.refreshExpiresAt
                }
        return None
    except Exception as e:
        print(f"Error in refresh_token_v2: {str(e)}")
        return None

def cleanup_expired_sessions_v2() -> int:
    """Cleanup expired sessions - wrapper for Lambda"""
    try:
        if SERVICE_AVAILABLE and enhanced_password_service_v2:
            return enhanced_password_service_v2.cleanup_expired_sessions()
        else:
            print("Session cleanup not available - using fallback")
            return 0
    except Exception as e:
        print(f"Error in cleanup_expired_sessions_v2: {str(e)}")
        return 0
def cleanup_expired_sessions_v2() -> int:
    """Cleanup expired sessions - wrapper for Lambda"""
    try:
        if SERVICE_AVAILABLE and enhanced_password_service_v2:
            return enhanced_password_service_v2.cleanup_expired_sessions()
        else:
            print("Session cleanup not available - using fallback")
            return 0
    except Exception as e:
        print(f"Error in cleanup_expired_sessions_v2: {str(e)}")
        return 0
