#!/usr/bin/env python3
"""
Script to check the admin user in DynamoDB
"""
import boto3
import json

def check_admin_user():
    """Check the admin user in DynamoDB"""
    
    # Initialize DynamoDB client
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('PeopleTable')
    
    # Admin user email
    admin_email = "admin@awsugcbba.org"
    
    print(f"Checking admin user: {admin_email}")
    
    # Find the admin user
    try:
        response = table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('email').eq(admin_email)
        )
        
        if not response['Items']:
            print(f"❌ Admin user {admin_email} not found!")
            return False
            
        admin_user = response['Items'][0]
        print(f"✅ Admin user found!")
        print(f"📋 User details:")
        print(json.dumps(admin_user, indent=2, default=str))
        return True
            
    except Exception as e:
        print(f"❌ Error checking admin user: {e}")
        return False

if __name__ == "__main__":
    check_admin_user()