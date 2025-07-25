"""
Rate Limiting Service for Authentication Endpoints
Implements sliding window rate limiting with DynamoDB backend
"""

import json
import boto3
import os
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, Optional, Tuple
import hashlib


class RateLimiter:
    """
    Rate limiter implementation using DynamoDB for persistence
    Supports different rate limits for different endpoint types
    """
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.rate_limit_table_name = os.environ.get('RATE_LIMIT_TABLE_NAME', 'RateLimitTable')
        
        try:
            self.rate_limit_table = self.dynamodb.Table(self.rate_limit_table_name)
        except Exception:
            # Table might not exist yet
            self.rate_limit_table = None
    
    # Rate limit configurations (requests per time window)
    RATE_LIMITS = {
        'auth_login': {'requests': 5, 'window_minutes': 15},  # 5 login attempts per 15 minutes
        'auth_password_reset': {'requests': 3, 'window_minutes': 60},  # 3 reset requests per hour
        'auth_password_change': {'requests': 10, 'window_minutes': 60},  # 10 password changes per hour
        'auth_token_refresh': {'requests': 20, 'window_minutes': 15},  # 20 token refreshes per 15 minutes
        'auth_validate_password': {'requests': 10, 'window_minutes': 5},  # 10 validations per 5 minutes
        'default': {'requests': 100, 'window_minutes': 60}  # Default rate limit
    }
    
    def _get_client_identifier(self, event: Dict) -> str:
        """
        Generate a unique identifier for the client
        Uses IP address and User-Agent for identification
        """
        # Get IP address from various possible headers
        ip_address = (
            event.get('requestContext', {}).get('identity', {}).get('sourceIp') or
            event.get('headers', {}).get('X-Forwarded-For', '').split(',')[0].strip() or
            event.get('headers', {}).get('X-Real-IP') or
            'unknown'
        )
        
        # Get User-Agent for additional fingerprinting
        user_agent = event.get('headers', {}).get('User-Agent', 'unknown')
        
        # Create a hash of IP + User-Agent for privacy
        identifier = f"{ip_address}:{user_agent}"
        return hashlib.sha256(identifier.encode()).hexdigest()[:16]
    
    def _get_rate_limit_key(self, client_id: str, endpoint: str) -> str:
        """Generate the DynamoDB key for rate limiting"""
        return f"{endpoint}#{client_id}"
    
    def check_rate_limit(self, event: Dict, endpoint: str) -> Tuple[bool, Dict]:
        """
        Check if the request should be rate limited
        Returns (is_allowed, rate_limit_info)
        """
        if not self.rate_limit_table:
            # If table doesn't exist, allow the request but log warning
            print("⚠️ Rate limit table not available, allowing request")
            return True, {'status': 'no_table'}
        
        client_id = self._get_client_identifier(event)
        rate_limit_key = self._get_rate_limit_key(client_id, endpoint)
        
        # Get rate limit configuration
        config = self.RATE_LIMITS.get(endpoint, self.RATE_LIMITS['default'])
        max_requests = config['requests']
        window_minutes = config['window_minutes']
        
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=window_minutes)
        
        try:
            # Get current rate limit record
            response = self.rate_limit_table.get_item(Key={'id': rate_limit_key})
            
            if 'Item' in response:
                item = response['Item']
                last_reset = datetime.fromisoformat(item['lastReset'])
                current_count = int(item['requestCount'])
                
                # Check if we need to reset the window
                if last_reset < window_start:
                    # Reset the counter
                    current_count = 1
                    last_reset = now
                else:
                    # Increment the counter
                    current_count += 1
            else:
                # First request from this client
                current_count = 1
                last_reset = now
            
            # Check if rate limit is exceeded
            is_allowed = current_count <= max_requests
            
            # Update the record
            self.rate_limit_table.put_item(
                Item={
                    'id': rate_limit_key,
                    'requestCount': current_count,
                    'lastReset': last_reset.isoformat(),
                    'endpoint': endpoint,
                    'clientId': client_id,
                    'ttl': int((now + timedelta(hours=24)).timestamp())  # Auto-cleanup after 24 hours
                }
            )
            
            rate_limit_info = {
                'status': 'checked',
                'endpoint': endpoint,
                'current_count': current_count,
                'max_requests': max_requests,
                'window_minutes': window_minutes,
                'reset_time': (last_reset + timedelta(minutes=window_minutes)).isoformat(),
                'is_allowed': is_allowed
            }
            
            if not is_allowed:
                print(f"🚫 Rate limit exceeded for {endpoint}: {current_count}/{max_requests}")
            
            return is_allowed, rate_limit_info
            
        except Exception as e:
            print(f"❌ Error checking rate limit: {str(e)}")
            # On error, allow the request but log the issue
            return True, {'status': 'error', 'error': str(e)}
    
    def get_rate_limit_headers(self, rate_limit_info: Dict) -> Dict[str, str]:
        """
        Generate standard rate limiting headers
        """
        if rate_limit_info.get('status') != 'checked':
            return {}
        
        headers = {
            'X-RateLimit-Limit': str(rate_limit_info['max_requests']),
            'X-RateLimit-Remaining': str(max(0, rate_limit_info['max_requests'] - rate_limit_info['current_count'])),
            'X-RateLimit-Reset': rate_limit_info['reset_time']
        }
        
        return headers


def rate_limit_decorator(endpoint: str):
    """
    Decorator to apply rate limiting to authentication endpoints
    """
    def decorator(func):
        def wrapper(event, *args, **kwargs):
            rate_limiter = RateLimiter()
            is_allowed, rate_limit_info = rate_limiter.check_rate_limit(event, endpoint)
            
            if not is_allowed:
                # Return rate limit exceeded response
                headers = rate_limiter.get_rate_limit_headers(rate_limit_info)
                headers.update({
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
                })
                
                return {
                    'statusCode': 429,
                    'headers': headers,
                    'body': json.dumps({
                        'error': 'Rate limit exceeded',
                        'message': f'Too many requests. Try again in {rate_limit_info["window_minutes"]} minutes.',
                        'retry_after': rate_limit_info['reset_time']
                    })
                }
            
            # Execute the original function
            result = func(event, *args, **kwargs)
            
            # Add rate limiting headers to successful responses
            if isinstance(result, dict) and 'headers' in result:
                rate_limit_headers = rate_limiter.get_rate_limit_headers(rate_limit_info)
                result['headers'].update(rate_limit_headers)
            
            return result
        
        return wrapper
    return decorator


# Utility function for manual rate limit checking
def check_authentication_rate_limit(event: Dict, endpoint: str) -> Tuple[bool, Dict, Dict[str, str]]:
    """
    Utility function to check rate limits and return headers
    Returns (is_allowed, rate_limit_info, headers)
    """
    rate_limiter = RateLimiter()
    is_allowed, rate_limit_info = rate_limiter.check_rate_limit(event, endpoint)
    headers = rate_limiter.get_rate_limit_headers(rate_limit_info)
    
    return is_allowed, rate_limit_info, headers
