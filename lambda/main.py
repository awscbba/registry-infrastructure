"""
Main Lambda handler for the People Registry API
"""
import json
import logging
from typing import Dict, Any

# Import your API handler
from api_handler import lambda_handler as api_lambda_handler

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main Lambda handler that routes to the API handler
    """
    try:
        logger.info(f"API Lambda received event: {json.dumps(event, default=str)[:500]}...")
        
        # Call the actual API handler
        response = api_lambda_handler(event, context)
        
        logger.info(f"API Lambda response status: {response.get('statusCode', 'unknown')}")
        return response
        
    except Exception as e:
        logger.error(f"API Lambda handler error: {e}", exc_info=True)
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
