#!/usr/bin/env python3
"""
Script to diagnose the production 502 errors.

This script helps identify why the production API is returning 502 Bad Gateway errors.
"""

import json
import requests
import time
from datetime import datetime

def test_production_endpoints():
    """Test production endpoints to identify 502 error patterns"""
    
    print("🔍 Production API Diagnosis - 502 Bad Gateway Errors")
    print("=" * 60)
    
    api_base_url = "https://2t9blvt2c1.execute-api.us-east-1.amazonaws.com/prod"
    
    # Test endpoints that are failing
    test_endpoints = [
        "/v2/projects",
        "/v2/subscriptions", 
        "/v2/admin/dashboard",
        "/v2/people/test-id",
        "/health",  # If it exists
        "/",  # Root endpoint
    ]
    
    print(f"\n📊 Testing {len(test_endpoints)} endpoints...")
    print(f"Base URL: {api_base_url}")
    print(f"Time: {datetime.now().isoformat()}")
    
    results = []
    
    for endpoint in test_endpoints:
        print(f"\n🔍 Testing: {endpoint}")
        
        try:
            start_time = time.time()
            response = requests.get(
                f"{api_base_url}{endpoint}", 
                timeout=15.0,
                headers={
                    "User-Agent": "Production-Diagnosis-Script/1.0",
                    "Accept": "application/json"
                }
            )
            end_time = time.time()
            
            duration = round((end_time - start_time) * 1000, 2)
            
            result = {
                "endpoint": endpoint,
                "status_code": response.status_code,
                "duration_ms": duration,
                "headers": dict(response.headers),
                "body_preview": response.text[:200] if response.text else "",
                "success": response.status_code < 500
            }
            
            results.append(result)
            
            # Print immediate results
            status_emoji = "✅" if result["success"] else "❌"
            print(f"  {status_emoji} Status: {response.status_code}")
            print(f"  ⏱️  Duration: {duration}ms")
            
            if response.status_code == 502:
                print(f"  🚨 502 Bad Gateway - Lambda function not responding")
                print(f"  📝 Response: {response.text[:100]}...")
            elif response.status_code >= 500:
                print(f"  🚨 Server Error: {response.text[:100]}...")
            elif response.status_code == 404:
                print(f"  ℹ️  Not Found - Endpoint may not exist")
            elif response.status_code in [401, 403]:
                print(f"  🔒 Auth Error - Endpoint exists but requires authentication")
            else:
                print(f"  ✅ Success or expected error")
                
        except requests.exceptions.Timeout:
            result = {
                "endpoint": endpoint,
                "status_code": "TIMEOUT",
                "duration_ms": 15000,
                "error": "Request timeout after 15 seconds",
                "success": False
            }
            results.append(result)
            print(f"  ⏰ TIMEOUT - Request took longer than 15 seconds")
            
        except requests.exceptions.ConnectionError as e:
            result = {
                "endpoint": endpoint,
                "status_code": "CONNECTION_ERROR",
                "error": str(e),
                "success": False
            }
            results.append(result)
            print(f"  🔌 CONNECTION ERROR: {str(e)[:100]}...")
            
        except Exception as e:
            result = {
                "endpoint": endpoint,
                "status_code": "ERROR",
                "error": str(e),
                "success": False
            }
            results.append(result)
            print(f"  ❌ ERROR: {str(e)[:100]}...")
    
    # Summary
    print(f"\n📊 SUMMARY")
    print("=" * 60)
    
    total_endpoints = len(results)
    successful = len([r for r in results if r.get("success", False)])
    failed_502 = len([r for r in results if r.get("status_code") == 502])
    failed_other = len([r for r in results if not r.get("success", False) and r.get("status_code") != 502])
    
    print(f"Total endpoints tested: {total_endpoints}")
    print(f"Successful responses: {successful}")
    print(f"502 Bad Gateway errors: {failed_502}")
    print(f"Other failures: {failed_other}")
    
    if failed_502 > 0:
        print(f"\n🚨 DIAGNOSIS: 502 Bad Gateway Errors Detected")
        print("This indicates that API Gateway cannot reach the Lambda functions.")
        print("Possible causes:")
        print("1. 🐛 Lambda function is crashing on startup")
        print("2. 🐛 Lambda function timeout (taking too long to respond)")
        print("3. 🐛 Lambda function out of memory")
        print("4. 🐛 ECR image issues (missing dependencies, wrong architecture)")
        print("5. 🐛 Environment variable issues")
        print("6. 🐛 X-Ray tracing configuration issues")
        print("7. 🐛 DynamoDB permissions or connection issues")
    
    print(f"\n🔧 RECOMMENDED ACTIONS:")
    print("1. Check CloudWatch Logs for Lambda function errors")
    print("2. Check X-Ray traces for failed requests")
    print("3. Test Lambda function directly (not through API Gateway)")
    print("4. Verify ECR image and dependencies")
    print("5. Check Lambda function environment variables")
    print("6. Verify DynamoDB table permissions")
    
    # Save detailed results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"production_diagnosis_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "api_base_url": api_base_url,
            "summary": {
                "total_endpoints": total_endpoints,
                "successful": successful,
                "failed_502": failed_502,
                "failed_other": failed_other
            },
            "results": results
        }, f, indent=2)
    
    print(f"\n📄 Detailed results saved to: {filename}")
    
    return results

if __name__ == "__main__":
    try:
        results = test_production_endpoints()
        
        # Exit with error code if there are 502 errors
        failed_502 = len([r for r in results if r.get("status_code") == 502])
        if failed_502 > 0:
            print(f"\n❌ Exiting with error code due to {failed_502} 502 errors")
            exit(1)
        else:
            print(f"\n✅ No 502 errors detected")
            exit(0)
            
    except Exception as e:
        print(f"\n❌ Script failed: {e}")
        exit(1)
