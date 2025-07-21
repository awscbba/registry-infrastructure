"""
Security Utilities for Input Sanitization and XSS Protection
Provides comprehensive input validation and sanitization functions
"""

import re
import html
import json
from typing import Any, Dict, List, Union
import urllib.parse


class SecurityUtils:
    """
    Comprehensive security utilities for input sanitization and validation
    """
    
    # XSS patterns to detect and remove
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'onload\s*=',
        r'onerror\s*=',
        r'onclick\s*=',
        r'onmouseover\s*=',
        r'onfocus\s*=',
        r'onblur\s*=',
        r'onchange\s*=',
        r'onsubmit\s*=',
        r'<iframe[^>]*>.*?</iframe>',
        r'<object[^>]*>.*?</object>',
        r'<embed[^>]*>.*?</embed>',
        r'<link[^>]*>',
        r'<meta[^>]*>',
        r'<style[^>]*>.*?</style>',
        r'expression\s*\(',
        r'url\s*\(',
        r'@import',
        r'<\s*img[^>]*src\s*=\s*["\']?\s*data:',
    ]
    
    # SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)',
        r'(\b(OR|AND)\s+\d+\s*=\s*\d+)',
        r'(\b(OR|AND)\s+["\']?\w+["\']?\s*=\s*["\']?\w+["\']?)',
        r'(--|#|/\*|\*/)',
        r'(\bxp_\w+)',
        r'(\bsp_\w+)',
        r'(\bEXEC\s*\()',
    ]
    
    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r'[;&|`$(){}[\]<>]',
        r'\b(cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp)\b',
        r'(\.\./|\.\.\\)',
        r'(/etc/passwd|/etc/shadow|/proc/)',
    ]
    
    @staticmethod
    def sanitize_string(input_string: str, max_length: int = 1000) -> str:
        """
        Sanitize a string input by removing XSS patterns and encoding HTML
        """
        if not isinstance(input_string, str):
            return str(input_string)
        
        # Truncate if too long
        if len(input_string) > max_length:
            input_string = input_string[:max_length]
        
        # Remove XSS patterns
        for pattern in SecurityUtils.XSS_PATTERNS:
            input_string = re.sub(pattern, '', input_string, flags=re.IGNORECASE | re.DOTALL)
        
        # HTML encode to prevent XSS
        input_string = html.escape(input_string)
        
        # URL decode to handle encoded attacks
        input_string = urllib.parse.unquote(input_string)
        
        # Remove null bytes and control characters
        input_string = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_string)
        
        return input_string.strip()
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Validate email format with security considerations
        """
        if not email or len(email) > 254:  # RFC 5321 limit
            return False
        
        # Basic email regex that prevents common injection attempts
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, email):
            return False
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'[<>"\']',  # HTML/script injection
            r'javascript:',
            r'data:',
            r'\s',  # No spaces allowed
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, email, re.IGNORECASE):
                return False
        
        return True
    
    @staticmethod
    def validate_phone(phone: str) -> bool:
        """
        Validate phone number format
        """
        if not phone:
            return False
        
        # Remove common formatting characters
        clean_phone = re.sub(r'[\s\-\(\)\+\.]', '', phone)
        
        # Check if it's all digits and reasonable length
        if not clean_phone.isdigit() or len(clean_phone) < 7 or len(clean_phone) > 15:
            return False
        
        return True
    
    @staticmethod
    def detect_sql_injection(input_string: str) -> bool:
        """
        Detect potential SQL injection attempts
        """
        if not isinstance(input_string, str):
            return False
        
        for pattern in SecurityUtils.SQL_INJECTION_PATTERNS:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def detect_command_injection(input_string: str) -> bool:
        """
        Detect potential command injection attempts
        """
        if not isinstance(input_string, str):
            return False
        
        for pattern in SecurityUtils.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def sanitize_json_input(json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively sanitize JSON input data
        """
        if isinstance(json_data, dict):
            sanitized = {}
            for key, value in json_data.items():
                # Sanitize the key
                clean_key = SecurityUtils.sanitize_string(str(key), max_length=100)
                
                # Recursively sanitize the value
                sanitized[clean_key] = SecurityUtils.sanitize_json_input(value)
            
            return sanitized
        
        elif isinstance(json_data, list):
            return [SecurityUtils.sanitize_json_input(item) for item in json_data]
        
        elif isinstance(json_data, str):
            return SecurityUtils.sanitize_string(json_data)
        
        else:
            # For numbers, booleans, None, return as-is
            return json_data
    
    @staticmethod
    def validate_password_input(password: str) -> Dict[str, Any]:
        """
        Validate password input for security requirements
        """
        if not isinstance(password, str):
            return {'valid': False, 'errors': ['Password must be a string']}
        
        errors = []
        
        # Length check
        if len(password) < 8:
            errors.append('Password must be at least 8 characters long')
        
        if len(password) > 128:
            errors.append('Password must be less than 128 characters long')
        
        # Character requirements
        if not re.search(r'[a-z]', password):
            errors.append('Password must contain at least one lowercase letter')
        
        if not re.search(r'[A-Z]', password):
            errors.append('Password must contain at least one uppercase letter')
        
        if not re.search(r'\d', password):
            errors.append('Password must contain at least one number')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append('Password must contain at least one special character')
        
        # Security checks
        if SecurityUtils.detect_sql_injection(password):
            errors.append('Password contains invalid characters')
        
        if SecurityUtils.detect_command_injection(password):
            errors.append('Password contains invalid characters')
        
        # Common weak passwords
        weak_patterns = [
            r'password',
            r'123456',
            r'qwerty',
            r'admin',
            r'letmein',
            r'welcome',
        ]
        
        for pattern in weak_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                errors.append('Password is too common or weak')
                break
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'strength_score': SecurityUtils._calculate_password_strength(password)
        }
    
    @staticmethod
    def _calculate_password_strength(password: str) -> int:
        """
        Calculate password strength score (0-100)
        """
        score = 0
        
        # Length bonus
        if len(password) >= 8:
            score += 20
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 10
        
        # Character variety
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 15
        
        # Complexity bonus
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.7:
            score += 15
        
        return min(score, 100)
    
    @staticmethod
    def generate_security_headers() -> Dict[str, str]:
        """
        Generate comprehensive security headers
        """
        return {
            # XSS Protection
            'X-XSS-Protection': '1; mode=block',
            
            # Content Type Options
            'X-Content-Type-Options': 'nosniff',
            
            # Frame Options
            'X-Frame-Options': 'DENY',
            
            # Content Security Policy
            'Content-Security-Policy': (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self' https:; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self'"
            ),
            
            # HSTS (HTTP Strict Transport Security)
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            
            # Referrer Policy
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            
            # Permissions Policy
            'Permissions-Policy': (
                'geolocation=(), '
                'microphone=(), '
                'camera=(), '
                'payment=(), '
                'usb=(), '
                'magnetometer=(), '
                'gyroscope=(), '
                'speaker=()'
            ),
            
            # Cache Control for sensitive endpoints
            'Cache-Control': 'no-store, no-cache, must-revalidate, private',
            'Pragma': 'no-cache',
            'Expires': '0'
        }
    
    @staticmethod
    def log_security_event(event_type: str, details: Dict[str, Any], client_info: Dict[str, Any]):
        """
        Log security events for monitoring and analysis
        """
        security_log = {
            'timestamp': SecurityUtils._get_current_timestamp(),
            'event_type': event_type,
            'details': details,
            'client_info': client_info,
            'severity': SecurityUtils._get_event_severity(event_type)
        }
        
        # In production, this would send to CloudWatch Logs or a SIEM
        print(f"🔒 SECURITY EVENT: {json.dumps(security_log)}")
    
    @staticmethod
    def _get_current_timestamp() -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.utcnow().isoformat()
    
    @staticmethod
    def _get_event_severity(event_type: str) -> str:
        """Determine severity level for security events"""
        high_severity = ['sql_injection', 'xss_attempt', 'command_injection', 'rate_limit_exceeded']
        medium_severity = ['invalid_input', 'weak_password', 'failed_validation']
        
        if event_type in high_severity:
            return 'HIGH'
        elif event_type in medium_severity:
            return 'MEDIUM'
        else:
            return 'LOW'


# Decorator for automatic input sanitization
def sanitize_inputs(func):
    """
    Decorator to automatically sanitize function inputs
    """
    def wrapper(event, *args, **kwargs):
        if isinstance(event, dict) and 'body' in event:
            try:
                # Parse and sanitize JSON body
                if event['body']:
                    body = json.loads(event['body'])
                    sanitized_body = SecurityUtils.sanitize_json_input(body)
                    event['body'] = json.dumps(sanitized_body)
            except json.JSONDecodeError:
                # If body is not JSON, sanitize as string
                if event['body']:
                    event['body'] = SecurityUtils.sanitize_string(event['body'])
        
        return func(event, *args, **kwargs)
    
    return wrapper
