#!/usr/bin/env python3
"""
Script to create the admin user in DynamoDB
Run this from the registry-infrastructure directory with devbox shell
"""
import boto3
import bcrypt
import uuid
from datetime import datetime
import sys
import os

def hash_password(password):
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def create_admin_user():
    """Create the admin user in DynamoDB"""
    
    # Initialize DynamoDB client
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('PeopleTable')
    
    # Admin user data
    admin_email = "admin@awsugcbba.org"
    admin_password = "admin123"  # You should change this to a secure password
    
    print(f"Creating admin user: {admin_email}")
    
    # Check if admin user already exists
    try:
        response = table.scan(
            FilterExpression=boto3.dynamodb.conditions.Attr('email').eq(admin_email)
        )
        
        if response['Items']:
            print(f"❌ Admin user {admin_email} already exists!")
            print("If you need to reset the password, delete the user first or update the password directly.")
            return False
            
    except Exception as e:
        print(f"❌ Error checking for existing admin user: {e}")
        return False
    
    # Create admin user
    admin_user = {
        'id': str(uuid.uuid4()),
        'email': admin_email,
        'firstName': 'Admin',
        'lastName': 'User',
        'password_hash': hash_password(admin_password),
        'phone': '+591 00000000',
        'dateOfBirth': '1990-01-01',
        'address': {
            'street': 'Admin Street',
            'city': 'Cochabamba',
            'state': 'Cochabamba',
            'zipCode': '0000',
            'country': 'Bolivia'
        },
        'createdAt': datetime.utcnow().isoformat(),
        'updatedAt': datetime.utcnow().isoformat(),
        'isAdmin': True,  # Add admin flag
        'requirePasswordChange': False  # Set to True if you want to force password change on first login
    }
    
    try:
        # Insert admin user
        table.put_item(Item=admin_user)
        print(f"✅ Admin user created successfully!")
        print(f"📧 Email: {admin_email}")
        print(f"🔑 Password: {admin_password}")
        print(f"🆔 User ID: {admin_user['id']}")
        print(f"⚠️  IMPORTANT: Please change the password after first login!")
        print(f"🌐 You can now login at: https://d28z2il3z2vmpc.cloudfront.net")
        return True
        
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Creating admin user for People Register application...")
    print("=" * 60)
    
    success = create_admin_user()
    
    if success:
        print("=" * 60)
        print("✅ Admin user creation completed successfully!")
        print("You can now test the login functionality.")
    else:
        print("=" * 60)
        print("❌ Admin user creation failed!")
        sys.exit(1)
