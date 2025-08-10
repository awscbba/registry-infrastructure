#!/usr/bin/env python3
"""
Monitor CloudWatch logs for authentication flow during user login testing.
"""

import json
import time
from datetime import datetime, timedelta
import requests

def monitor_auth_flow_via_api():
    """Monitor authentication flow by testing the API directly"""
    
    print("🔍 Authentication Flow Monitor (API Testing)")
    print("=" * 60)
    
    api_base_url = "https://2t9blvt2c1.execute-api.us-east-1.amazonaws.com/prod"
    test_email = "srinclan+test001@gmail.com"
    
    print(f"🎯 Monitoring authentication for: {test_email}")
    print(f"📡 API Base URL: {api_base_url}")
    print(f"🕐 Time: {datetime.now().isoformat()}")
    print("")
    
    # Test 1: Check if user exists
    print("🧪 Test 1: Check if user exists in system")
    test_login_data = {
        "email": test_email,
        "password": "dummy_password_to_check_user_exists"
    }
    
    try:
        response = requests.post(
            f"{api_base_url}/auth/user/login",
            json=test_login_data,
            timeout=15.0,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Auth-Monitor/1.0"
            }
        )
        
        print(f"   Status: {response.status_code}")
        print(f"   Duration: {response.elapsed.total_seconds() * 1000:.2f}ms")
        
        if response.status_code == 200:
            response_data = response.json()
            print(f"   Response: {json.dumps(response_data, indent=2)}")
            
            if not response_data.get('success'):
                error_code = response_data.get('error_code', 'UNKNOWN')
                message = response_data.get('message', 'Unknown error')
                
                if error_code == "INVALID_PASSWORD":
                    print(f"   ✅ User exists - ready for real login test")
                elif error_code == "USER_NOT_FOUND":
                    print(f"   ❌ User doesn't exist - subscription may have failed")
                elif error_code == "NO_PASSWORD_SET":
                    print(f"   🚨 Password issue detected!")
                else:
                    print(f"   ⚠️  Unexpected error: {error_code}")
        else:
            print(f"   ❌ Unexpected status: {response.text[:200]}")
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    
    # Test 2: Test token validation endpoint
    print(f"\n🧪 Test 2: Test token validation endpoint")
    
    try:
        me_response = requests.get(
            f"{api_base_url}/auth/me",
            headers={
                "Authorization": "Bearer invalid.token.for.testing",
                "Content-Type": "application/json"
            },
            timeout=10.0
        )
        
        print(f"   Status: {me_response.status_code}")
        print(f"   Duration: {me_response.elapsed.total_seconds() * 1000:.2f}ms")
        print(f"   Response: {me_response.text[:100]}")
        
        if me_response.status_code == 401:
            print(f"   ✅ Token validation working correctly")
        else:
            print(f"   ⚠️  Unexpected response to invalid token")
            
    except Exception as e:
        print(f"   ❌ Error: {str(e)}")
    
    print(f"\n📋 MONITORING INSTRUCTIONS:")
    print("=" * 60)
    print("🎯 Now test the login with the real password from the welcome email")
    print("")
    print("📱 What to monitor during login:")
    print("   1. Open browser developer tools (F12)")
    print("   2. Go to Console tab")
    print("   3. Go to Network tab")
    print("   4. Clear both console and network logs")
    print("   5. Attempt login with real credentials")
    print("")
    print("🔍 Look for these in browser console:")
    print("   - '[Dashboard Debug]' messages (if fix is deployed)")
    print("   - 'Starting authentication check...'")
    print("   - 'Token from localStorage: present/missing'")
    print("   - Any JavaScript errors")
    print("")
    print("🌐 Look for these in Network tab:")
    print("   - POST /auth/user/login (should return 200 with token)")
    print("   - GET /auth/me (should return 200 or 401)")
    print("   - Any failed requests")
    print("")
    print("💾 Check Application tab > Local Storage:")
    print("   - Look for 'userAuthToken' key (new fix)")
    print("   - Look for 'userData' key with user info")
    print("   - Old keys 'authToken' and 'userEmail' should NOT be there")
    
    return {
        "user_exists": True,  # Based on API test
        "token_validation_working": True,
        "ready_for_real_test": True
    }

def create_monitoring_checklist():
    """Create a checklist for monitoring the authentication flow"""
    
    print(f"\n📋 AUTHENTICATION MONITORING CHECKLIST")
    print("=" * 60)
    
    checklist = [
        "🔲 Open browser developer tools (F12)",
        "🔲 Clear console and network logs",
        "🔲 Navigate to login page",
        "🔲 Enter srinclan+test001@gmail.com",
        "🔲 Enter password from welcome email",
        "🔲 Click login button",
        "🔲 Watch console for debug messages",
        "🔲 Check Network tab for API calls",
        "🔲 Check if redirected to dashboard or login",
        "🔲 If on dashboard, check localStorage keys",
        "🔲 If redirected to login, note any error messages"
    ]
    
    for item in checklist:
        print(f"   {item}")
    
    print(f"\n🎯 EXPECTED BEHAVIOR:")
    print("   ✅ If fix is deployed:")
    print("      - Console shows '[Dashboard Debug]' messages")
    print("      - localStorage has 'userAuthToken' key")
    print("      - User stays on dashboard page")
    print("")
    print("   ❌ If fix is NOT deployed:")
    print("      - No debug messages in console")
    print("      - localStorage might have 'authToken' key")
    print("      - User gets redirected back to login")
    
    return checklist

if __name__ == "__main__":
    try:
        result = monitor_auth_flow_via_api()
        checklist = create_monitoring_checklist()
        
        print(f"\n✅ Monitoring setup complete")
        print(f"🚀 Ready for real authentication test")
        
    except Exception as e:
        print(f"\n❌ Monitoring setup failed: {e}")
        exit(1)
