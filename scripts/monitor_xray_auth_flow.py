#!/usr/bin/env python3
"""
Monitor X-Ray traces for authentication flow during user login testing.
"""

import json
import time
from datetime import datetime, timedelta
import boto3

def monitor_xray_auth_flow():
    """Monitor X-Ray traces for authentication flow"""
    
    print("🔍 X-Ray Authentication Flow Monitor")
    print("=" * 60)
    
    # Initialize X-Ray client
    try:
        xray_client = boto3.client('xray', region_name='us-east-1')
        print("✅ X-Ray client initialized")
    except Exception as e:
        print(f"❌ Failed to initialize X-Ray client: {e}")
        return
    
    # Set time range for monitoring (last 5 minutes)
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(minutes=5)
    
    print(f"📊 Monitoring traces from {start_time.isoformat()} to {end_time.isoformat()}")
    print(f"🎯 Looking for authentication-related traces...")
    print(f"👤 Test user: srinclan+test001@gmail.com")
    print("")
    
    try:
        # Get trace summaries
        response = xray_client.get_trace_summaries(
            TimeRangeType='TimeRangeByStartTime',
            StartTime=start_time,
            EndTime=end_time,
            FilterExpression='service("people-registry-api") OR service("people-registry-auth")'
        )
        
        traces = response.get('TraceSummaries', [])
        print(f"📈 Found {len(traces)} traces in the last 5 minutes")
        
        if not traces:
            print("ℹ️  No recent traces found. This could mean:")
            print("   - X-Ray tracing is not enabled")
            print("   - No API requests in the last 5 minutes")
            print("   - Service names don't match the filter")
            print("")
            print("🔧 Try making a login request now and run this script again")
            return
        
        # Analyze each trace
        for i, trace in enumerate(traces[:10]):  # Limit to 10 most recent
            trace_id = trace['Id']
            duration = trace.get('Duration', 0)
            response_time = trace.get('ResponseTime', 0)
            has_error = trace.get('HasError', False)
            has_fault = trace.get('HasFault', False)
            
            print(f"\n🔍 Trace {i+1}: {trace_id}")
            print(f"   ⏱️  Duration: {duration:.3f}s")
            print(f"   📡 Response Time: {response_time:.3f}s")
            print(f"   ❌ Has Error: {has_error}")
            print(f"   🚨 Has Fault: {has_fault}")
            
            # Get detailed trace
            try:
                trace_detail = xray_client.batch_get_traces(
                    TraceIds=[trace_id]
                )
                
                if trace_detail.get('Traces'):
                    trace_data = trace_detail['Traces'][0]
                    segments = trace_data.get('Segments', [])
                    
                    print(f"   📊 Segments: {len(segments)}")
                    
                    # Analyze segments for authentication patterns
                    for segment in segments:
                        try:
                            segment_doc = json.loads(segment['Document'])
                            segment_name = segment_doc.get('name', 'Unknown')
                            
                            # Look for authentication-related segments
                            if any(keyword in segment_name.lower() for keyword in ['auth', 'login', 'user', 'token']):
                                print(f"   🔐 Auth Segment: {segment_name}")
                                
                                # Check for errors in this segment
                                if segment_doc.get('error'):
                                    print(f"      ❌ Error: {segment_doc.get('cause', {}).get('message', 'Unknown error')}")
                                
                                # Check for HTTP information
                                http_info = segment_doc.get('http', {})
                                if http_info:
                                    print(f"      📡 HTTP: {http_info.get('request', {}).get('method', 'Unknown')} {http_info.get('request', {}).get('url', 'Unknown')}")
                                    print(f"      📊 Status: {http_info.get('response', {}).get('status', 'Unknown')}")
                                
                                # Check for DynamoDB operations
                                aws_info = segment_doc.get('aws', {})
                                if 'dynamodb' in aws_info:
                                    print(f"      🗄️  DynamoDB: {aws_info.get('operation', 'Unknown operation')}")
                                    print(f"      📋 Table: {aws_info.get('table_name', 'Unknown table')}")
                        
                        except json.JSONDecodeError:
                            print(f"   ⚠️  Could not parse segment document")
                        except Exception as e:
                            print(f"   ⚠️  Error analyzing segment: {e}")
                            
            except Exception as e:
                print(f"   ❌ Error getting trace details: {e}")
        
        print(f"\n📋 MONITORING SUMMARY:")
        print(f"   Total traces: {len(traces)}")
        print(f"   Traces with errors: {sum(1 for t in traces if t.get('HasError'))}")
        print(f"   Traces with faults: {sum(1 for t in traces if t.get('HasFault'))}")
        
        if traces:
            avg_duration = sum(t.get('Duration', 0) for t in traces) / len(traces)
            print(f"   Average duration: {avg_duration:.3f}s")
        
        print(f"\n🎯 WHAT TO LOOK FOR:")
        print("   - Authentication-related segments")
        print("   - DynamoDB query operations")
        print("   - HTTP 401/403 responses")
        print("   - Token validation errors")
        print("   - Long response times")
        
    except Exception as e:
        print(f"❌ Error monitoring X-Ray traces: {e}")
        print("This might be due to:")
        print("  - X-Ray not enabled on Lambda functions")
        print("  - Insufficient permissions")
        print("  - No recent traces available")

def monitor_real_time():
    """Monitor X-Ray traces in real-time"""
    print("\n🔄 REAL-TIME MONITORING")
    print("=" * 60)
    print("Monitoring for new traces every 10 seconds...")
    print("Press Ctrl+C to stop")
    print("")
    
    try:
        while True:
            print(f"🕐 {datetime.now().strftime('%H:%M:%S')} - Checking for new traces...")
            monitor_xray_auth_flow()
            print("\n" + "="*60)
            time.sleep(10)
    except KeyboardInterrupt:
        print("\n👋 Monitoring stopped")

if __name__ == "__main__":
    try:
        monitor_xray_auth_flow()
        
        # Ask if user wants real-time monitoring
        print(f"\n❓ Would you like to start real-time monitoring?")
        print("   This will check for new traces every 10 seconds")
        print("   Run: python scripts/monitor_xray_auth_flow.py --realtime")
        
    except Exception as e:
        print(f"\n❌ Monitoring failed: {e}")
        exit(1)
