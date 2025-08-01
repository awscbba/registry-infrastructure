#!/usr/bin/env python3
"""
Script to delete the admin user from DynamoDB
"""
import boto3

def delete_admin_user():
    """Delete the admin user from DynamoDB"""
    
    # Initialize DynamoDB client
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('PeopleTable')
    
    # Admin user email
    admin_email = "admin@awsugcbba.org"
    
    print(f"Deleting admin user: {admin_email}")
    
    # Find the admin user
    try:
        response = table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('email').eq(admin_email)
        )
        
        if not response['Items']:
            print(f"❌ Admin user {admin_email} not found!")
            return False
            
        admin_user = response['Items'][0]
        user_id = admin_user['id']
        
        # Delete the user
        table.delete_item(Key={'id': user_id})
        print(f"✅ Admin user {admin_email} deleted successfully!")
        return True
            
    except Exception as e:
        print(f"❌ Error deleting admin user: {e}")
        return False

if __name__ == "__main__":
    delete_admin_user()