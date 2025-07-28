"""
Simple routing Lambda that forwards requests to appropriate backend Lambda functions.
This solves the API Gateway policy size limit issue by having a single integration point.
"""
import json
import boto3
import os
from typing import Dict, Any

# Initialize Lambda client
lambda_client = boto3.client('lambda')

# Get Lambda function names from environment variables
AUTH_FUNCTION_NAME = os.environ['AUTH_FUNCTION_NAME']
API_FUNCTION_NAME = os.environ['API_FUNCTION_NAME']

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Route requests to appropriate Lambda functions based on path.
    
    Routing rules:
    - /auth/* -> AuthFunction
    - Everything else -> PeopleApiFunction
    """
    
    # Extract path from the event
    path = event.get('path', '')
    http_method = event.get('httpMethod', 'GET')
    
    # Determine target function based on path
    if path.startswith('/auth'):
        target_function = AUTH_FUNCTION_NAME
    else:
        target_function = API_FUNCTION_NAME
    
    try:
        # Forward the request to the appropriate Lambda function
        response = lambda_client.invoke(
            FunctionName=target_function,
            InvocationType='RequestResponse',
            Payload=json.dumps(event)
        )
        
        # Parse the response
        payload = json.loads(response['Payload'].read())
        
        return payload
        
    except Exception as e:
        # Return error response
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
                'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
            },
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }