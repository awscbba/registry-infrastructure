#!/usr/bin/env python3
"""
Create Standardized DynamoDB Tables
Creates new DynamoDB tables with consistent camelCase schema for the People Registry.
"""

import boto3
from botocore.exceptions import ClientError
import json
import sys
from datetime import datetime
from typing import Dict, Any


class StandardizedTableCreator:
    """Creates standardized DynamoDB tables with consistent camelCase schema."""
    
    def __init__(self):
        self.dynamodb = boto3.client('dynamodb')
        self.resource = boto3.resource('dynamodb')
        
        # New standardized table names (with v2 suffix to avoid conflicts)
        self.new_tables = {
            'people': 'PeopleTableV2',
            'projects': 'ProjectsTableV2',
            'subscriptions': 'SubscriptionsTableV2'
        }
        
        self.table_schemas = self._define_standardized_schemas()
    
    def _define_standardized_schemas(self) -> Dict[str, Dict[str, Any]]:
        """Define standardized schemas for all tables."""
        return {
            'people': {
                'TableName': self.new_tables['people'],
                'KeySchema': [
                    {'AttributeName': 'id', 'KeyType': 'HASH'}
                ],
                'AttributeDefinitions': [
                    {'AttributeName': 'id', 'AttributeType': 'S'},
                    {'AttributeName': 'email', 'AttributeType': 'S'}
                ],
                'BillingMode': 'PAY_PER_REQUEST',
                'GlobalSecondaryIndexes': [
                    {
                        'IndexName': 'EmailIndex',
                        'KeySchema': [
                            {'AttributeName': 'email', 'KeyType': 'HASH'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'}
                    }
                ],
                'PointInTimeRecoverySpecification': {
                    'PointInTimeRecoveryEnabled': True
                },
                'Tags': [
                    {'Key': 'Environment', 'Value': 'production'},
                    {'Key': 'Application', 'Value': 'people-registry'},
                    {'Key': 'Version', 'Value': 'v2-standardized'}
                ]
            },
            'projects': {
                'TableName': self.new_tables['projects'],
                'KeySchema': [
                    {'AttributeName': 'id', 'KeyType': 'HASH'}
                ],
                'AttributeDefinitions': [
                    {'AttributeName': 'id', 'AttributeType': 'S'},
                    {'AttributeName': 'status', 'AttributeType': 'S'},
                    {'AttributeName': 'category', 'AttributeType': 'S'}
                ],
                'BillingMode': 'PAY_PER_REQUEST',
                'GlobalSecondaryIndexes': [
                    {
                        'IndexName': 'StatusIndex',
                        'KeySchema': [
                            {'AttributeName': 'status', 'KeyType': 'HASH'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'}
                    },
                    {
                        'IndexName': 'CategoryIndex',
                        'KeySchema': [
                            {'AttributeName': 'category', 'KeyType': 'HASH'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'}
                    }
                ],
                'PointInTimeRecoverySpecification': {
                    'PointInTimeRecoveryEnabled': True
                },
                'Tags': [
                    {'Key': 'Environment', 'Value': 'production'},
                    {'Key': 'Application', 'Value': 'people-registry'},
                    {'Key': 'Version', 'Value': 'v2-standardized'}
                ]
            },
            'subscriptions': {
                'TableName': self.new_tables['subscriptions'],
                'KeySchema': [
                    {'AttributeName': 'id', 'KeyType': 'HASH'}
                ],
                'AttributeDefinitions': [
                    {'AttributeName': 'id', 'AttributeType': 'S'},
                    {'AttributeName': 'personId', 'AttributeType': 'S'},
                    {'AttributeName': 'projectId', 'AttributeType': 'S'},
                    {'AttributeName': 'status', 'AttributeType': 'S'}
                ],
                'BillingMode': 'PAY_PER_REQUEST',
                'GlobalSecondaryIndexes': [
                    {
                        'IndexName': 'PersonIndex',
                        'KeySchema': [
                            {'AttributeName': 'personId', 'KeyType': 'HASH'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'}
                    },
                    {
                        'IndexName': 'ProjectIndex',
                        'KeySchema': [
                            {'AttributeName': 'projectId', 'KeyType': 'HASH'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'}
                    },
                    {
                        'IndexName': 'StatusIndex',
                        'KeySchema': [
                            {'AttributeName': 'status', 'KeyType': 'HASH'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'}
                    }
                ],
                'PointInTimeRecoverySpecification': {
                    'PointInTimeRecoveryEnabled': True
                },
                'Tags': [
                    {'Key': 'Environment', 'Value': 'production'},
                    {'Key': 'Application', 'Value': 'people-registry'},
                    {'Key': 'Version', 'Value': 'v2-standardized'}
                ]
            }
        }
    
    def create_all_tables(self) -> Dict[str, bool]:
        """Create all standardized tables."""
        print("🏗️  Creating Standardized DynamoDB Tables...")
        print("=" * 60)
        
        results = {}
        
        for table_type, schema in self.table_schemas.items():
            table_name = schema['TableName']
            print(f"\n📊 Creating {table_type.upper()} table ({table_name})...")
            
            try:
                # Check if table already exists
                if self._table_exists(table_name):
                    print(f"   ⚠️  Table {table_name} already exists, skipping...")
                    results[table_type] = True
                    continue
                
                # Create table
                response = self.dynamodb.create_table(**schema)
                print(f"   ✅ Table {table_name} creation initiated")
                
                # Wait for table to be active
                print(f"   ⏳ Waiting for table {table_name} to become active...")
                waiter = self.dynamodb.get_waiter('table_exists')
                waiter.wait(TableName=table_name)
                
                print(f"   🎉 Table {table_name} is now active!")
                results[table_type] = True
                
            except ClientError as e:
                print(f"   ❌ Error creating table {table_name}: {e}")
                results[table_type] = False
            except Exception as e:
                print(f"   ❌ Unexpected error creating table {table_name}: {e}")
                results[table_type] = False
        
        self._print_creation_summary(results)
        return results
    
    def _table_exists(self, table_name: str) -> bool:
        """Check if a table already exists."""
        try:
            self.dynamodb.describe_table(TableName=table_name)
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return False
            raise
    
    def _print_creation_summary(self, results: Dict[str, bool]):
        """Print summary of table creation results."""
        print("\n" + "=" * 60)
        print("📋 TABLE CREATION SUMMARY")
        print("=" * 60)
        
        successful = sum(1 for success in results.values() if success)
        total = len(results)
        
        print(f"✅ Successfully created: {successful}/{total} tables")
        
        for table_type, success in results.items():
            table_name = self.new_tables[table_type]
            status = "✅ SUCCESS" if success else "❌ FAILED"
            print(f"   {table_type.upper()}: {table_name} - {status}")
        
        if successful == total:
            print("\n🎉 All standardized tables created successfully!")
            self._print_next_steps()
        else:
            print(f"\n⚠️  {total - successful} tables failed to create. Please check the errors above.")
    
    def _print_next_steps(self):
        """Print next steps after successful table creation."""
        print("\n" + "=" * 60)
        print("🚀 NEXT STEPS")
        print("=" * 60)
        print("1. ✅ Standardized tables created")
        print("2. 🔄 Run data migration script to copy data from old tables")
        print("3. 🧪 Test API with new tables")
        print("4. 🚀 Deploy API updates to use new tables")
        print("5. 🗑️  Clean up old tables after successful migration")
        
        print("\n📋 NEW TABLE NAMES:")
        for table_type, table_name in self.new_tables.items():
            print(f"   {table_type.upper()}: {table_name}")
    
    def get_standardized_schema_documentation(self) -> Dict[str, Any]:
        """Get documentation of the standardized schema."""
        return {
            "people_table_schema": {
                "required_fields": [
                    "id",           # string - unique identifier
                    "email",        # string - email address (unique)
                    "firstName",    # string - first name
                    "lastName",     # string - last name
                    "phone",        # string - phone number (can be empty)
                    "dateOfBirth",  # string - YYYY-MM-DD format
                    "address",      # object - complete address
                    "isAdmin",      # boolean - admin status
                    "isActive",     # boolean - account status
                    "emailVerified", # boolean - email verification status
                    "requirePasswordChange", # boolean - password change required
                    "createdAt",    # string - ISO timestamp
                    "updatedAt"     # string - ISO timestamp
                ],
                "optional_fields": [
                    "lastLoginAt",  # string - ISO timestamp
                    "failedLoginAttempts", # number - failed login count
                    "passwordHash", # string - hashed password
                    "passwordSalt"  # string - password salt
                ],
                "address_structure": {
                    "street": "string",      # street address
                    "city": "string",        # city name
                    "state": "string",       # state/province
                    "postalCode": "string",  # postal/zip code
                    "country": "string"      # country name
                }
            },
            "projects_table_schema": {
                "required_fields": [
                    "id",               # string - unique identifier
                    "name",             # string - project name
                    "description",      # string - project description
                    "startDate",        # string - YYYY-MM-DD format
                    "endDate",          # string - YYYY-MM-DD format
                    "maxParticipants",  # number - maximum participants
                    "currentParticipants", # number - current participant count
                    "status",           # string - pending/active/completed/cancelled
                    "createdBy",        # string - creator user ID
                    "createdAt",        # string - ISO timestamp
                    "updatedAt"         # string - ISO timestamp
                ],
                "optional_fields": [
                    "category",         # string - project category
                    "location",         # string - project location
                    "requirements"      # string - project requirements
                ]
            },
            "subscriptions_table_schema": {
                "required_fields": [
                    "id",           # string - unique identifier
                    "personId",     # string - person ID (foreign key)
                    "projectId",    # string - project ID (foreign key)
                    "status",       # string - active/inactive/cancelled
                    "subscribedAt", # string - ISO timestamp
                    "createdAt",    # string - ISO timestamp
                    "updatedAt"     # string - ISO timestamp
                ],
                "optional_fields": [
                    "subscribedBy", # string - who created the subscription
                    "personName",   # string - cached person name
                    "personEmail",  # string - cached person email
                    "projectName",  # string - cached project name
                    "emailSent",    # boolean - confirmation email sent
                    "version"       # number - record version for optimistic locking
                ]
            }
        }
    
    def save_schema_documentation(self, filename: str = None):
        """Save schema documentation to a JSON file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"standardized_schema_documentation_{timestamp}.json"
        
        schema_doc = self.get_standardized_schema_documentation()
        
        with open(filename, 'w') as f:
            json.dump(schema_doc, f, indent=2)
        
        print(f"📋 Schema documentation saved to: {filename}")


def main():
    """Main function to create standardized tables."""
    try:
        creator = StandardizedTableCreator()
        
        # Create all tables
        results = creator.create_all_tables()
        
        # Save schema documentation
        creator.save_schema_documentation()
        
        # Return exit code based on results
        if all(results.values()):
            print("\n🎉 All standardized tables created successfully!")
            return 0
        else:
            failed_count = sum(1 for success in results.values() if not success)
            print(f"\n❌ {failed_count} tables failed to create")
            return 1
            
    except Exception as e:
        print(f"\n❌ Error during table creation: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())