#!/usr/bin/env python3
"""
Script to create the DynamoDB table for role-based access control.
"""

import boto3
import logging
import sys
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_roles_table(table_name: str = "people-registry-roles", region: str = "us-east-1"):
    """
    Create the DynamoDB table for storing user roles.
    
    Args:
        table_name: Name of the DynamoDB table
        region: AWS region to create the table in
    """
    try:
        # Initialize DynamoDB client
        dynamodb = boto3.client('dynamodb', region_name=region)
        
        logger.info(f"Creating DynamoDB table: {table_name}")
        
        # Define table schema
        table_definition = {
            'TableName': table_name,
            'KeySchema': [
                {
                    'AttributeName': 'user_id',
                    'KeyType': 'HASH'  # Partition key
                },
                {
                    'AttributeName': 'role_type',
                    'KeyType': 'RANGE'  # Sort key
                }
            ],
            'AttributeDefinitions': [
                {
                    'AttributeName': 'user_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'role_type',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'email',
                    'AttributeType': 'S'
                }
            ],
            'GlobalSecondaryIndexes': [
                {
                    'IndexName': 'email-index',
                    'KeySchema': [
                        {
                            'AttributeName': 'email',
                            'KeyType': 'HASH'
                        }
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    }
                }
            ],
            'BillingMode': 'PAY_PER_REQUEST',
            'Tags': [
                {
                    'Key': 'Project',
                    'Value': 'people-registry'
                },
                {
                    'Key': 'Component',
                    'Value': 'roles'
                },
                {
                    'Key': 'Environment',
                    'Value': 'production'
                }
            ]
        }
        
        # Create the table
        response = dynamodb.create_table(**table_definition)
        
        logger.info(f"Table creation initiated. Status: {response['TableDescription']['TableStatus']}")
        
        # Wait for table to be created
        logger.info("Waiting for table to be created...")
        waiter = dynamodb.get_waiter('table_exists')
        waiter.wait(
            TableName=table_name,
            WaiterConfig={
                'Delay': 5,
                'MaxAttempts': 60
            }
        )
        
        # Verify table creation
        table_info = dynamodb.describe_table(TableName=table_name)
        logger.info(f"✅ Table '{table_name}' created successfully!")
        logger.info(f"Table ARN: {table_info['Table']['TableArn']}")
        logger.info(f"Table Status: {table_info['Table']['TableStatus']}")
        
        # Display table details
        logger.info("\nTable Details:")
        logger.info(f"  - Partition Key: user_id (String)")
        logger.info(f"  - Sort Key: role_type (String)")
        logger.info(f"  - Global Secondary Index: email-index")
        logger.info(f"  - Billing Mode: PAY_PER_REQUEST")
        
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        
        if error_code == 'ResourceInUseException':
            logger.warning(f"Table '{table_name}' already exists.")
            
            # Check if the existing table has the correct schema
            try:
                table_info = dynamodb.describe_table(TableName=table_name)
                logger.info("Verifying existing table schema...")
                
                # Basic schema verification
                key_schema = table_info['Table']['KeySchema']
                partition_key = next((k for k in key_schema if k['KeyType'] == 'HASH'), None)
                sort_key = next((k for k in key_schema if k['KeyType'] == 'RANGE'), None)
                
                if (partition_key and partition_key['AttributeName'] == 'user_id' and
                    sort_key and sort_key['AttributeName'] == 'role_type'):
                    logger.info("✅ Existing table has correct schema.")
                    return True
                else:
                    logger.error("❌ Existing table has incorrect schema.")
                    logger.error("Please delete the existing table or use a different name.")
                    return False
                    
            except Exception as verify_error:
                logger.error(f"Error verifying existing table: {str(verify_error)}")
                return False
                
        else:
            logger.error(f"Error creating table: {e.response['Error']['Message']}")
            return False
            
    except Exception as e:
        logger.error(f"Unexpected error creating table: {str(e)}")
        return False


def create_audit_log_table(table_name: str = "people-registry-audit-logs", region: str = "us-east-1"):
    """
    Create the DynamoDB table for storing audit logs.
    
    Args:
        table_name: Name of the DynamoDB table
        region: AWS region to create the table in
    """
    try:
        # Initialize DynamoDB client
        dynamodb = boto3.client('dynamodb', region_name=region)
        
        logger.info(f"Creating DynamoDB audit log table: {table_name}")
        
        # Define table schema
        table_definition = {
            'TableName': table_name,
            'KeySchema': [
                {
                    'AttributeName': 'log_id',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            'AttributeDefinitions': [
                {
                    'AttributeName': 'log_id',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'timestamp',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'admin_user_id',
                    'AttributeType': 'S'
                }
            ],
            'GlobalSecondaryIndexes': [
                {
                    'IndexName': 'timestamp-index',
                    'KeySchema': [
                        {
                            'AttributeName': 'timestamp',
                            'KeyType': 'HASH'
                        }
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    }
                },
                {
                    'IndexName': 'admin-user-index',
                    'KeySchema': [
                        {
                            'AttributeName': 'admin_user_id',
                            'KeyType': 'HASH'
                        },
                        {
                            'AttributeName': 'timestamp',
                            'KeyType': 'RANGE'
                        }
                    ],
                    'Projection': {
                        'ProjectionType': 'ALL'
                    }
                }
            ],
            'BillingMode': 'PAY_PER_REQUEST',
            'Tags': [
                {
                    'Key': 'Project',
                    'Value': 'people-registry'
                },
                {
                    'Key': 'Component',
                    'Value': 'audit-logs'
                },
                {
                    'Key': 'Environment',
                    'Value': 'production'
                }
            ]
        }
        
        # Create the table
        response = dynamodb.create_table(**table_definition)
        
        logger.info(f"Audit log table creation initiated. Status: {response['TableDescription']['TableStatus']}")
        
        # Wait for table to be created
        logger.info("Waiting for audit log table to be created...")
        waiter = dynamodb.get_waiter('table_exists')
        waiter.wait(
            TableName=table_name,
            WaiterConfig={
                'Delay': 5,
                'MaxAttempts': 60
            }
        )
        
        logger.info(f"✅ Audit log table '{table_name}' created successfully!")
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            logger.warning(f"Audit log table '{table_name}' already exists.")
            return True
        else:
            logger.error(f"Error creating audit log table: {e.response['Error']['Message']}")
            return False
            
    except Exception as e:
        logger.error(f"Unexpected error creating audit log table: {str(e)}")
        return False


def main():
    """
    Main function to create both tables.
    """
    logger.info("Starting DynamoDB table creation for role-based access control...")
    
    success = True
    
    # Create roles table
    if not create_roles_table():
        success = False
    
    # Create audit log table
    if not create_audit_log_table():
        success = False
    
    if success:
        logger.info("\n🎉 All tables created successfully!")
        logger.info("\nNext steps:")
        logger.info("1. Run the migration script to populate initial admin roles")
        logger.info("2. Update your application to use the new role-based middleware")
        logger.info("3. Test the new access control system")
    else:
        logger.error("\n❌ Some tables failed to create. Please check the errors above.")
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
