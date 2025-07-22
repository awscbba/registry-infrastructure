"""
Password management service for handling secure password operations.
"""
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict, Any
import os
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import bcrypt
import secrets
import string
import re
import uuid

logger = logging.getLogger(__name__)


# Password Policy Configuration
class PasswordPolicy:
    """Password security policy configuration."""
    MIN_LENGTH = 8
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_NUMBERS = True
    REQUIRE_SPECIAL_CHARS = True
    PREVENT_REUSE_COUNT = 5
    SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"


# Password Utilities
class PasswordValidator:
    """Validates passwords against security policy."""
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, List[str]]:
        """Validate password against security policy."""
        errors = []
        
        if len(password) < PasswordPolicy.MIN_LENGTH:
            errors.append(f"Password must be at least {PasswordPolicy.MIN_LENGTH} characters long")
        
        if PasswordPolicy.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if PasswordPolicy.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if PasswordPolicy.REQUIRE_NUMBERS and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if PasswordPolicy.REQUIRE_SPECIAL_CHARS:
            special_char_pattern = f"[{re.escape(PasswordPolicy.SPECIAL_CHARS)}]"
            if not re.search(special_char_pattern, password):
                errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors


class PasswordHasher:
    """Handles secure password hashing and verification."""
    
    SALT_ROUNDS = 12
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt with salt."""
        salt = bcrypt.gensalt(rounds=PasswordHasher.SALT_ROUNDS)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        except (ValueError, TypeError):
            return False


class PasswordGenerator:
    """Generates secure random passwords."""
    
    @staticmethod
    def generate_secure_password(length: int = 12) -> str:
        """Generate a secure random password that meets policy requirements."""
        if length < PasswordPolicy.MIN_LENGTH:
            length = PasswordPolicy.MIN_LENGTH
        
        password_chars = []
        
        if PasswordPolicy.REQUIRE_UPPERCASE:
            password_chars.append(secrets.choice(string.ascii_uppercase))
        
        if PasswordPolicy.REQUIRE_LOWERCASE:
            password_chars.append(secrets.choice(string.ascii_lowercase))
        
        if PasswordPolicy.REQUIRE_NUMBERS:
            password_chars.append(secrets.choice(string.digits))
        
        if PasswordPolicy.REQUIRE_SPECIAL_CHARS:
            password_chars.append(secrets.choice(PasswordPolicy.SPECIAL_CHARS))
        
        all_chars = string.ascii_letters + string.digits + PasswordPolicy.SPECIAL_CHARS
        remaining_length = length - len(password_chars)
        
        for _ in range(remaining_length):
            password_chars.append(secrets.choice(all_chars))
        
        secrets.SystemRandom().shuffle(password_chars)
        return ''.join(password_chars)


class PasswordHistoryManager:
    """Manages password history for reuse prevention."""
    
    @staticmethod
    def add_to_history(current_history: List[str], new_password_hash: str) -> List[str]:
        """Add a new password hash to history and maintain the limit."""
        if current_history is None:
            current_history = []
        
        updated_history = [new_password_hash] + current_history
        return updated_history[:PasswordPolicy.PREVENT_REUSE_COUNT]
    
    @staticmethod
    def can_use_password(password: str, password_history: List[str]) -> Tuple[bool, str]:
        """Check if a password can be used (not in recent history)."""
        if not password_history:
            return True, ""
        
        for old_hash in password_history:
            if PasswordHasher.verify_password(password, old_hash):
                return False, f"Cannot reuse any of the last {PasswordPolicy.PREVENT_REUSE_COUNT} passwords"
        return True, ""


def hash_and_validate_password(password: str, password_history: List[str] = None) -> Tuple[bool, str, List[str]]:
    """Validate and hash a password in one operation."""
    is_valid, errors = PasswordValidator.validate_password(password)
    if not is_valid:
        return False, "", errors
    
    if password_history:
        can_use, reuse_error = PasswordHistoryManager.can_use_password(password, password_history)
        if not can_use:
            return False, "", [reuse_error]
    
    hashed_password = PasswordHasher.hash_password(password)
    return True, hashed_password, []


# Models
class PasswordUpdateRequest:
    """Request model for password updates."""
    def __init__(self, current_password: str, new_password: str, confirm_password: str):
        self.current_password = current_password
        self.new_password = new_password
        self.confirm_password = confirm_password
        
        if new_password != confirm_password:
            raise ValueError("Passwords do not match")


class PasswordUpdateResponse:
    """Response model for password update operations."""
    def __init__(self, success: bool, message: str, require_reauth: bool = True):
        self.success = success
        self.message = message
        self.require_reauth = require_reauth


class SecurityEvent:
    """Security event model for audit logging."""
    def __init__(self, person_id: str, action: str, timestamp: datetime, 
                 ip_address: str = None, user_agent: str = None, 
                 success: bool = True, details: Dict = None):
        self.person_id = person_id
        self.action = action
        self.timestamp = timestamp
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.success = success
        self.details = details or {}


# Database Service
class DynamoDBService:
    """Simplified DynamoDB service for password management."""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.table_name = os.environ.get('PEOPLE_TABLE_NAME', 'PeopleTable')
        self.table = self.dynamodb.Table(self.table_name)
        self.audit_table_name = os.environ.get('AUDIT_LOGS_TABLE_NAME', 'AuditLogsTable')
        
        try:
            self.audit_table = self.dynamodb.Table(self.audit_table_name)
        except Exception:
            self.audit_table = None
    
    async def get_person(self, person_id: str):
        """Get a person by ID."""
        try:
            response = self.table.get_item(Key={'id': person_id})
            if 'Item' in response:
                item = response['Item']
                # Create a simple person object
                person = type('Person', (), {})()
                person.id = item['id']
                person.password_hash = item.get('passwordHash')
                person.password_history = item.get('passwordHistory', [])
                return person
            return None
        except ClientError as e:
            logger.error(f"Error getting person {person_id}: {e}")
            return None
    
    async def log_security_event(self, security_event: SecurityEvent):
        """Log a security event to the audit table."""
        if not self.audit_table:
            return
            
        try:
            item = {
                'id': str(datetime.utcnow().timestamp()) + '_' + security_event.person_id,
                'personId': security_event.person_id,
                'action': security_event.action,
                'timestamp': security_event.timestamp.isoformat(),
                'success': security_event.success
            }
            
            if security_event.ip_address:
                item['ipAddress'] = security_event.ip_address
            if security_event.user_agent:
                item['userAgent'] = security_event.user_agent
            if security_event.details:
                item['details'] = security_event.details
            
            self.audit_table.put_item(Item=item)
        except ClientError as e:
            logger.error(f"Failed to log security event: {e}")


class PasswordManagementService:
    """Service for managing password operations with security and validation."""
    
    def __init__(self):
        self.db_service = DynamoDBService()
    
    async def update_password(
        self,
        person_id: str,
        password_request: PasswordUpdateRequest,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[bool, PasswordUpdateResponse, Optional[str]]:
        """Update a person's password with validation and security checks."""
        try:
            # Get the person from database
            person = await self.db_service.get_person(person_id)
            if not person:
                await self._log_security_event(
                    person_id=person_id,
                    action="PASSWORD_UPDATE_FAILED",
                    success=False,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={"reason": "person_not_found"}
                )
                return False, PasswordUpdateResponse(
                    success=False,
                    message="Person not found"
                ), "Person not found"
            
            # Validate current password
            if not await self._validate_current_password(person, password_request.current_password):
                await self._log_security_event(
                    person_id=person_id,
                    action="PASSWORD_UPDATE_FAILED",
                    success=False,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={"reason": "invalid_current_password"}
                )
                return False, PasswordUpdateResponse(
                    success=False,
                    message="Current password is incorrect"
                ), "Current password is incorrect"
            
            # Validate new password against policy and history
            is_valid, hashed_password, validation_errors = await self._validate_new_password(
                person, password_request.new_password
            )
            
            if not is_valid:
                await self._log_security_event(
                    person_id=person_id,
                    action="PASSWORD_UPDATE_FAILED",
                    success=False,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={"reason": "password_validation_failed", "errors": validation_errors}
                )
                return False, PasswordUpdateResponse(
                    success=False,
                    message="; ".join(validation_errors)
                ), "; ".join(validation_errors)
            
            # Update password in database
            success = await self._update_password_in_database(
                person_id, hashed_password, person.password_history or []
            )
            
            if not success:
                await self._log_security_event(
                    person_id=person_id,
                    action="PASSWORD_UPDATE_FAILED",
                    success=False,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={"reason": "database_update_failed"}
                )
                return False, PasswordUpdateResponse(
                    success=False,
                    message="Failed to update password"
                ), "Failed to update password"
            
            # Log successful password update
            await self._log_security_event(
                person_id=person_id,
                action="PASSWORD_UPDATED",
                success=True,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"require_reauth": True}
            )
            
            return True, PasswordUpdateResponse(
                success=True,
                message="Password updated successfully",
                require_reauth=True
            ), None
            
        except Exception as e:
            logger.error(f"Error updating password for person {person_id}: {str(e)}")
            await self._log_security_event(
                person_id=person_id,
                action="PASSWORD_UPDATE_FAILED",
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "system_error", "error": str(e)}
            )
            return False, PasswordUpdateResponse(
                success=False,
                message="System error occurred"
            ), "System error occurred"
    
    async def validate_password_change_request(
        self,
        person_id: str,
        current_password: str
    ) -> Tuple[bool, Optional[str]]:
        """Validate a password change request by verifying the current password."""
        try:
            person = await self.db_service.get_person(person_id)
            if not person:
                return False, "Person not found"
            
            is_valid = await self._validate_current_password(person, current_password)
            if not is_valid:
                return False, "Current password is incorrect"
            
            return True, None
            
        except Exception as e:
            logger.error(f"Error validating password change request for person {person_id}: {str(e)}")
            return False, "System error occurred"
    
    async def force_password_change(
        self,
        person_id: str,
        admin_user_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """Force a password change requirement for a person (admin function)."""
        try:
            person = await self.db_service.get_person(person_id)
            if not person:
                return False, "Person not found"
            
            # Update require_password_change flag
            success = await self._update_password_change_requirement(person_id, True)
            
            if success:
                await self._log_security_event(
                    person_id=person_id,
                    action="PASSWORD_CHANGE_FORCED",
                    success=True,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={"forced_by": admin_user_id}
                )
                return True, None
            else:
                return False, "Failed to force password change"
                
        except Exception as e:
            logger.error(f"Error forcing password change for person {person_id}: {str(e)}")
            return False, "System error occurred"
    
    async def generate_temporary_password(
        self,
        person_id: str,
        admin_user_id: str,
        length: int = 12,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Generate a temporary password for a person (admin function)."""
        try:
            person = await self.db_service.get_person(person_id)
            if not person:
                return False, None, "Person not found"
            
            # Generate secure temporary password
            temp_password = PasswordGenerator.generate_secure_password(length)
            hashed_password = PasswordHasher.hash_password(temp_password)
            
            # Update password in database and force password change
            success = await self._update_password_in_database(
                person_id, hashed_password, person.password_history or [], require_change=True
            )
            
            if success:
                await self._log_security_event(
                    person_id=person_id,
                    action="TEMPORARY_PASSWORD_GENERATED",
                    success=True,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={"generated_by": admin_user_id, "require_change": True}
                )
                return True, temp_password, None
            else:
                return False, None, "Failed to set temporary password"
                
        except Exception as e:
            logger.error(f"Error generating temporary password for person {person_id}: {str(e)}")
            return False, None, "System error occurred"
    
    async def check_password_history(
        self,
        person_id: str,
        password: str
    ) -> Tuple[bool, Optional[str]]:
        """Check if a password has been used recently."""
        try:
            person = await self.db_service.get_person(person_id)
            if not person:
                return False, "Person not found"
            
            can_use, error_msg = PasswordHistoryManager.can_use_password(
                password, person.password_history or []
            )
            
            return can_use, error_msg if not can_use else None
            
        except Exception as e:
            logger.error(f"Error checking password history for person {person_id}: {str(e)}")
            return False, "System error occurred"
    
    async def _validate_current_password(self, person, current_password: str) -> bool:
        """Validate the current password for a person."""
        if not hasattr(person, 'password_hash') or not person.password_hash:
            return False
        
        return PasswordHasher.verify_password(current_password, person.password_hash)
    
    async def _validate_new_password(
        self,
        person,
        new_password: str
    ) -> Tuple[bool, str, List[str]]:
        """Validate a new password against policy and history."""
        return hash_and_validate_password(new_password, person.password_history or [])
    
    async def _update_password_in_database(
        self,
        person_id: str,
        hashed_password: str,
        current_history: List[str],
        require_change: bool = False
    ) -> bool:
        """Update password in the database with history management."""
        try:
            # Update password history
            updated_history = PasswordHistoryManager.add_to_history(
                current_history, hashed_password
            )
            
            # Prepare update expression
            now = datetime.now(timezone.utc)
            update_expression = """
                SET passwordHash = :password_hash,
                    passwordHistory = :password_history,
                    lastPasswordChange = :last_change,
                    updatedAt = :updated_at
            """
            
            expression_values = {
                ':password_hash': hashed_password,
                ':password_history': updated_history,
                ':last_change': now.isoformat(),
                ':updated_at': now.isoformat()
            }
            
            if require_change:
                update_expression += ", requirePasswordChange = :require_change"
                expression_values[':require_change'] = True
            
            # Update in DynamoDB
            self.db_service.table.update_item(
                Key={'id': person_id},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating password in database for person {person_id}: {str(e)}")
            return False
    
    async def _update_password_change_requirement(
        self,
        person_id: str,
        require_change: bool
    ) -> bool:
        """Update the password change requirement flag."""
        try:
            self.db_service.table.update_item(
                Key={'id': person_id},
                UpdateExpression="SET requirePasswordChange = :require_change, updatedAt = :updated_at",
                ExpressionAttributeValues={
                    ':require_change': require_change,
                    ':updated_at': datetime.now(timezone.utc).isoformat()
                }
            )
            return True
            
        except Exception as e:
            logger.error(f"Error updating password change requirement for person {person_id}: {str(e)}")
            return False
    
    async def _log_security_event(
        self,
        person_id: str,
        action: str,
        success: bool,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log a security event for audit purposes."""
        try:
            security_event = SecurityEvent(
                person_id=person_id,
                action=action,
                timestamp=datetime.now(timezone.utc),
                ip_address=ip_address,
                user_agent=user_agent,
                success=success,
                details=details
            )
            
            await self.db_service.log_security_event(security_event)
            
        except Exception as e:
            logger.error(f"Error logging security event: {str(e)}")