# Placeholder Lambda handler
# Actual implementation is deployed by registry-api repository
# This file exists only to satisfy CDK bundling requirements

def lambda_handler(event, context):
    """
    Placeholder handler - will be replaced by registry-api deployment
    """
    return {
        'statusCode': 503,
        'body': 'Service temporarily unavailable - Lambda code not yet deployed by registry-api'
    }