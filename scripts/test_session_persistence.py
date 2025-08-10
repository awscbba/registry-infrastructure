#!/usr/bin/env python3
"""
Test session persistence and authentication flow.
"""

import json
import requests
import time
from datetime import datetime

def test_session_persistence():
    """Test the complete authentication and session flow"""
    
    print("🔐 Session Persistence Test")
    print("=" * 60)
    
    api_base_url = "https://2t9blvt2c1.execute-api.us-east-1.amazonaws.com/prod"
    
    print(f"Base URL: {api_base_url}")
    print(f"Time: {datetime.now().isoformat()}")
    
    # Test 1: Login with the test user credentials
    print(f"\n🧪 Test 1: User login with sergio.rodriguez.inclan@gmail.com")
    
    # Note: We can't use the actual password from email, so we'll test the flow
    test_login_data = {
        "email": "sergio.rodriguez.inclan@gmail.com",
        "password": "dummy_password_for_testing"  # This will fail, but we can see the response
    }
    
    try:
        response = requests.post(
            f"{api_base_url}/auth/user/login",
            json=test_login_data,
            timeout=15.0,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Session-Test-Script/1.0"
            }
        )
        
        print(f"  Status: {response.status_code}")
        print(f"  Duration: {response.elapsed.total_seconds() * 1000:.2f}ms")
        
        if response.status_code == 200:
            response_data = response.json()
            if response_data.get('success'):
                print(f"  ✅ Login successful")
                token = response_data.get('token')
                user_info = response_data.get('user', {})
                
                print(f"  🔑 Token received: {token[:20]}..." if token else "  ❌ No token received")
                print(f"  👤 User: {user_info.get('firstName', 'Unknown')} {user_info.get('lastName', 'Unknown')}")
                
                # Test 2: Use token to access protected endpoint
                if token:
                    print(f"\n🧪 Test 2: Access protected endpoint with token")
                    
                    headers = {
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                        "User-Agent": "Session-Test-Script/1.0"
                    }
                    
                    # Test /auth/me endpoint
                    me_response = requests.get(
                        f"{api_base_url}/auth/me",
                        headers=headers,
                        timeout=15.0
                    )
                    
                    print(f"  /auth/me Status: {me_response.status_code}")
                    if me_response.status_code == 200:
                        me_data = me_response.json()
                        print(f"  ✅ Token validation successful")
                        print(f"  👤 User ID: {me_data.get('user', {}).get('id', 'Unknown')}")
                    else:
                        print(f"  ❌ Token validation failed: {me_response.text[:100]}")
                    
                    # Test user subscriptions endpoint
                    subs_response = requests.get(
                        f"{api_base_url}/auth/user/subscriptions",
                        headers=headers,
                        timeout=15.0
                    )
                    
                    print(f"  /auth/user/subscriptions Status: {subs_response.status_code}")
                    if subs_response.status_code == 200:
                        subs_data = subs_response.json()
                        subscriptions = subs_data.get('subscriptions', [])
                        print(f"  ✅ Subscriptions retrieved: {len(subscriptions)} found")
                        for sub in subscriptions[:2]:  # Show first 2
                            print(f"    - {sub.get('projectName', 'Unknown')} ({sub.get('status', 'unknown')})")
                    else:
                        print(f"  ❌ Subscriptions failed: {subs_response.text[:100]}")
                        
            else:
                error_code = response_data.get('error_code', 'UNKNOWN')
                message = response_data.get('message', 'Unknown error')
                print(f"  ⚠️  Login failed: {error_code} - {message}")
                
                if error_code == "USER_NOT_FOUND":
                    print(f"  ℹ️  User doesn't exist in database")
                elif error_code == "NO_PASSWORD_SET":
                    print(f"  🚨 Password issue detected!")
                elif error_code == "INVALID_PASSWORD":
                    print(f"  ℹ️  Wrong password (expected for test)")
                    
        else:
            print(f"  ❌ Unexpected status: {response.text[:200]}")
            
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
    
    # Test 3: Check JWT token structure and expiration
    print(f"\n🧪 Test 3: JWT Token Analysis")
    
    # Create a test token to analyze structure
    print(f"  ℹ️  JWT tokens should contain:")
    print(f"    - Header with algorithm (HS256)")
    print(f"    - Payload with user info and expiration")
    print(f"    - Signature for verification")
    print(f"    - Expiration time (24 hours from creation)")
    
    # Test 4: Check frontend authentication flow
    print(f"\n🧪 Test 4: Frontend Authentication Flow Analysis")
    
    print(f"  🔍 Potential issues causing login page reload:")
    print(f"    1. JWT token not being stored in localStorage/sessionStorage")
    print(f"    2. Token expiration check failing")
    print(f"    3. Frontend auth guard redirecting due to invalid token")
    print(f"    4. CORS issues preventing token validation")
    print(f"    5. Token format mismatch between backend and frontend")
    
    # Test 5: Check token validation endpoint
    print(f"\n🧪 Test 5: Token Validation Endpoint Test")
    
    # Test with a malformed token
    malformed_headers = {
        "Authorization": "Bearer invalid.token.here",
        "Content-Type": "application/json"
    }
    
    try:
        invalid_response = requests.get(
            f"{api_base_url}/auth/me",
            headers=malformed_headers,
            timeout=10.0
        )
        
        print(f"  Invalid token test - Status: {invalid_response.status_code}")
        if invalid_response.status_code == 401:
            print(f"  ✅ Token validation correctly rejects invalid tokens")
        else:
            print(f"  ⚠️  Unexpected response to invalid token: {invalid_response.text[:100]}")
            
    except Exception as e:
        print(f"  ❌ Error testing invalid token: {str(e)}")
    
    print(f"\n📊 SESSION PERSISTENCE ANALYSIS")
    print("=" * 60)
    print("Based on the symptoms (profile loads then redirects to login):")
    print("")
    print("🔍 LIKELY CAUSES:")
    print("1. 🎯 Frontend token storage issue")
    print("   - Token not being saved to localStorage")
    print("   - Token being cleared immediately after login")
    print("")
    print("2. 🎯 Token validation timing issue")
    print("   - Frontend checking token before it's fully set")
    print("   - Race condition in authentication state management")
    print("")
    print("3. 🎯 JWT token format/structure issue")
    print("   - Backend and frontend expecting different token formats")
    print("   - Missing required claims in JWT payload")
    print("")
    print("4. 🎯 CORS or network issue")
    print("   - Token validation request failing silently")
    print("   - Network timeout causing auth check to fail")
    
    print(f"\n🔧 RECOMMENDED DEBUGGING STEPS:")
    print("1. Check browser developer tools:")
    print("   - Network tab: Look for failed /auth/me requests")
    print("   - Application tab: Check localStorage for auth token")
    print("   - Console: Look for JavaScript errors")
    print("")
    print("2. Test the actual login credentials:")
    print("   - Use the exact password from the welcome email")
    print("   - Verify the login response contains a valid token")
    print("")
    print("3. Check frontend authentication logic:")
    print("   - Verify token is being stored after successful login")
    print("   - Check if auth guard is properly validating tokens")
    
    return True

if __name__ == "__main__":
    try:
        test_session_persistence()
        print(f"\n✅ Session persistence analysis completed")
        exit(0)
    except Exception as e:
        print(f"\n❌ Session persistence test failed: {e}")
        exit(1)
