#!/usr/bin/env python3
"""
Debug the live authentication issue with real user credentials.
"""

import json
import requests
import time
from datetime import datetime

def debug_live_auth_issue():
    """Debug the authentication issue with real user"""
    
    print("🔍 Live Authentication Issue Debug")
    print("=" * 60)
    
    api_base_url = "https://2t9blvt2c1.execute-api.us-east-1.amazonaws.com/prod"
    
    print(f"Base URL: {api_base_url}")
    print(f"Time: {datetime.now().isoformat()}")
    
    # Test with the new user
    print(f"\n🧪 Testing authentication flow for srinclan+test001@gmail.com")
    
    # First, let's check if the user exists
    test_login_data = {
        "email": "srinclan+test001@gmail.com",
        "password": "dummy_password"  # Wrong password to see the error type
    }
    
    try:
        response = requests.post(
            f"{api_base_url}/auth/user/login",
            json=test_login_data,
            timeout=15.0,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Live-Auth-Debug/1.0"
            }
        )
        
        print(f"  Status: {response.status_code}")
        print(f"  Duration: {response.elapsed.total_seconds() * 1000:.2f}ms")
        
        if response.status_code == 200:
            response_data = response.json()
            print(f"  Response: {json.dumps(response_data, indent=2)}")
            
            if not response_data.get('success'):
                error_code = response_data.get('error_code', 'UNKNOWN')
                message = response_data.get('message', 'Unknown error')
                print(f"\n  📋 Error Analysis:")
                print(f"    Error Code: {error_code}")
                print(f"    Message: {message}")
                
                if error_code == "INVALID_PASSWORD":
                    print(f"    ✅ User exists - authentication backend is working")
                elif error_code == "USER_NOT_FOUND":
                    print(f"    ❌ User doesn't exist - subscription may have failed")
                elif error_code == "NO_PASSWORD_SET":
                    print(f"    ❌ Password issue detected!")
                    
        else:
            print(f"  ❌ Unexpected status: {response.text[:300]}")
            
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
    
    # Test the /auth/me endpoint with a dummy token to see the response format
    print(f"\n🧪 Testing /auth/me endpoint response format")
    
    try:
        me_response = requests.get(
            f"{api_base_url}/auth/me",
            headers={
                "Authorization": "Bearer invalid.token.here",
                "Content-Type": "application/json"
            },
            timeout=10.0
        )
        
        print(f"  Status: {me_response.status_code}")
        print(f"  Response: {me_response.text[:200]}")
        
        if me_response.status_code == 401:
            print(f"  ✅ /auth/me correctly rejects invalid tokens")
        else:
            print(f"  ⚠️  Unexpected response to invalid token")
            
    except Exception as e:
        print(f"  ❌ Error testing /auth/me: {str(e)}")
    
    print(f"\n🔍 FRONTEND DEPLOYMENT STATUS CHECK")
    print("=" * 60)
    
    # Check if the frontend fix has been deployed by examining the current dashboard
    print("The issue persists, which suggests:")
    print("")
    print("1. 🚨 Frontend fix not deployed yet")
    print("   - The feature branch exists but may not be merged/deployed")
    print("   - Dashboard is still using old localStorage keys")
    print("")
    print("2. 🚨 Additional issues beyond localStorage keys")
    print("   - Token validation timing issues")
    print("   - CORS problems")
    print("   - JavaScript errors in browser")
    print("")
    print("3. 🚨 Token format or validation issues")
    print("   - Backend and frontend expecting different token formats")
    print("   - Token expiration issues")
    
    print(f"\n🔧 IMMEDIATE DEBUGGING STEPS NEEDED:")
    print("1. Check browser developer tools:")
    print("   - Open Network tab during login")
    print("   - Look for failed requests to /auth/me")
    print("   - Check Application tab for localStorage contents")
    print("   - Look for JavaScript console errors")
    print("")
    print("2. Verify frontend deployment:")
    print("   - Check if feature branch was merged to main")
    print("   - Verify if frontend pipeline deployed the changes")
    print("   - Test with browser cache cleared")
    print("")
    print("3. Test with real credentials:")
    print("   - Use actual password from welcome email")
    print("   - Monitor the complete login flow")
    print("   - Check what gets stored in localStorage")
    
    print(f"\n📋 POTENTIAL ADDITIONAL ISSUES:")
    print("1. 🎯 Race condition in authentication check")
    print("   - Dashboard checking auth before token is fully stored")
    print("   - Need to add delay or proper async handling")
    print("")
    print("2. 🎯 CORS or network issues")
    print("   - /auth/me request failing silently")
    print("   - Network timeout causing auth check to fail")
    print("")
    print("3. 🎯 JavaScript execution order")
    print("   - Auth check running before localStorage is populated")
    print("   - Need to ensure proper initialization order")
    print("")
    print("4. 🎯 Browser caching")
    print("   - Old version of dashboard.astro still cached")
    print("   - Need hard refresh or cache clear")
    
    print(f"\n🚀 NEXT STEPS:")
    print("1. Verify frontend deployment status")
    print("2. Test with browser developer tools open")
    print("3. Check for additional frontend issues")
    print("4. Consider adding debug logging to dashboard")
    
    return {
        "issue_persists": True,
        "likely_causes": [
            "Frontend fix not deployed",
            "Additional timing/race condition issues",
            "Browser caching old version"
        ]
    }

if __name__ == "__main__":
    try:
        result = debug_live_auth_issue()
        print(f"\n📊 DEBUG SUMMARY:")
        print(f"Issue persists: {result['issue_persists']}")
        print(f"Likely causes: {', '.join(result['likely_causes'])}")
        exit(0)
    except Exception as e:
        print(f"\n❌ Debug failed: {e}")
        exit(1)
