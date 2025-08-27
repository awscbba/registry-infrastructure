#!/usr/bin/env python3
"""
Data Migration Script for Standardized Tables
Migrates data from old tables to new standardized camelCase tables.
"""

import boto3
from botocore.exceptions import ClientError
import json
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
import uuid


class DataMigrator:
    """Migrates data from old tables to standardized tables."""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        
        # Table mappings: old -> new
        self.table_mappings = {
            'PeopleTable': 'PeopleTableV2',
            'ProjectsTable': 'ProjectsTableV2',
            'SubscriptionsTable': 'SubscriptionsTableV2'
        }
        
        self.migration_stats = {
            'people': {'migrated': 0, 'errors': 0, 'skipped': 0},
            'projects': {'migrated': 0, 'errors': 0, 'skipped': 0},
            'subscriptions': {'migrated': 0, 'errors': 0, 'skipped': 0}
        }
        
        self.errors = []
    
    def migrate_all_data(self) -> Dict[str, Any]:
        """Migrate data from all old tables to new standardized tables."""
        print("🔄 Starting Data Migration to Standardized Tables...")
        print("=" * 60)
        
        # Migrate in order: people -> projects -> subscriptions
        migration_order = ['people', 'projects', 'subscriptions']
        
        for table_type in migration_order:
            print(f"\n📊 Migrating {table_type.upper()} data...")
            try:
                if table_type == 'people':
                    self.migrate_people_data()
                elif table_type == 'projects':
                    self.migrate_projects_data()
                elif table_type == 'subscriptions':
                    self.migrate_subscriptions_data()
                    
                print(f"✅ {table_type.upper()} migration completed")
            except Exception as e:
                print(f"❌ Error migrating {table_type}: {str(e)}")
                self.errors.append(f"{table_type}: {str(e)}")
        
        self.print_migration_summary()
        return self.migration_stats
    
    def migrate_people_data(self):
        """Migrate people data with field standardization."""
        old_table = self.dynamodb.Table('PeopleTable')
        new_table = self.dynamodb.Table('PeopleTableV2')
        
        # Scan old table
        response = old_table.scan()
        items = response['Items']
        
        while 'LastEvaluatedKey' in response:
            response = old_table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            items.extend(response['Items'])
        
        print(f"   📈 Found {len(items)} people to migrate")
        
        for item in items:
            try:
                standardized_item = self.standardize_person_item(item)
                
                # Check if item already exists in new table
                if self.item_exists(new_table, standardized_item['id']):
                    print(f"   ⚠️  Person {standardized_item['id']} already exists, skipping...")
                    self.migration_stats['people']['skipped'] += 1
                    continue
                
                # Insert into new table
                new_table.put_item(Item=standardized_item)
                self.migration_stats['people']['migrated'] += 1
                
            except Exception as e:
                print(f"   ❌ Error migrating person {item.get('id', 'unknown')}: {str(e)}")
                self.migration_stats['people']['errors'] += 1
                self.errors.append(f"Person {item.get('id', 'unknown')}: {str(e)}")
    
    def migrate_projects_data(self):
        """Migrate projects data with field standardization."""
        old_table = self.dynamodb.Table('ProjectsTable')
        new_table = self.dynamodb.Table('ProjectsTableV2')
        
        # Scan old table
        response = old_table.scan()
        items = response['Items']
        
        while 'LastEvaluatedKey' in response:
            response = old_table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            items.extend(response['Items'])
        
        print(f"   📈 Found {len(items)} projects to migrate")
        
        for item in items:
            try:
                standardized_item = self.standardize_project_item(item)
                
                # Check if item already exists in new table
                if self.item_exists(new_table, standardized_item['id']):
                    print(f"   ⚠️  Project {standardized_item['id']} already exists, skipping...")
                    self.migration_stats['projects']['skipped'] += 1
                    continue
                
                # Insert into new table
                new_table.put_item(Item=standardized_item)
                self.migration_stats['projects']['migrated'] += 1
                
            except Exception as e:
                print(f"   ❌ Error migrating project {item.get('id', 'unknown')}: {str(e)}")
                self.migration_stats['projects']['errors'] += 1
                self.errors.append(f"Project {item.get('id', 'unknown')}: {str(e)}")
    
    def migrate_subscriptions_data(self):
        """Migrate subscriptions data with field standardization."""
        old_table = self.dynamodb.Table('SubscriptionsTable')
        new_table = self.dynamodb.Table('SubscriptionsTableV2')
        
        # Scan old table
        response = old_table.scan()
        items = response['Items']
        
        while 'LastEvaluatedKey' in response:
            response = old_table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            items.extend(response['Items'])
        
        print(f"   📈 Found {len(items)} subscriptions to migrate")
        
        for item in items:
            try:
                standardized_item = self.standardize_subscription_item(item)
                
                # Check if item already exists in new table
                if self.item_exists(new_table, standardized_item['id']):
                    print(f"   ⚠️  Subscription {standardized_item['id']} already exists, skipping...")
                    self.migration_stats['subscriptions']['skipped'] += 1
                    continue
                
                # Insert into new table
                new_table.put_item(Item=standardized_item)
                self.migration_stats['subscriptions']['migrated'] += 1
                
            except Exception as e:
                print(f"   ❌ Error migrating subscription {item.get('id', 'unknown')}: {str(e)}")
                self.migration_stats['subscriptions']['errors'] += 1
                self.errors.append(f"Subscription {item.get('id', 'unknown')}: {str(e)}")
    
    def standardize_person_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize a person item to camelCase schema."""
        now = datetime.utcnow().isoformat()
        
        # Create standardized item with required fields
        standardized = {
            'id': item.get('id', str(uuid.uuid4())),
            'email': item.get('email', ''),
            'firstName': item.get('firstName') or item.get('first_name', ''),
            'lastName': item.get('lastName') or item.get('last_name', ''),
            'phone': item.get('phone', ''),
            'dateOfBirth': item.get('dateOfBirth') or item.get('date_of_birth', ''),
            'isAdmin': item.get('isAdmin') or item.get('is_admin', False),
            'isActive': item.get('isActive') or item.get('is_active', True),
            'emailVerified': item.get('emailVerified') or item.get('email_verified', False),
            'requirePasswordChange': item.get('requirePasswordChange') or item.get('require_password_change', False),
            'createdAt': item.get('createdAt') or item.get('created_at', now),
            'updatedAt': item.get('updatedAt') or item.get('updated_at', now)
        }
        
        # Handle address - standardize to camelCase
        address = item.get('address', {})
        if address:
            standardized['address'] = {
                'street': address.get('street', ''),
                'city': address.get('city', ''),
                'state': address.get('state', ''),
                'postalCode': address.get('postalCode') or address.get('postal_code', ''),
                'country': address.get('country', '')
            }
        else:
            # Default empty address
            standardized['address'] = {
                'street': '',
                'city': '',
                'state': '',
                'postalCode': '',
                'country': ''
            }
        
        # Optional fields
        if 'lastLoginAt' in item or 'last_login_at' in item:
            standardized['lastLoginAt'] = item.get('lastLoginAt') or item.get('last_login_at')
        
        if 'failedLoginAttempts' in item or 'failed_login_attempts' in item:
            standardized['failedLoginAttempts'] = item.get('failedLoginAttempts') or item.get('failed_login_attempts', 0)
        
        if 'password_hash' in item:
            standardized['passwordHash'] = item['password_hash']
        
        if 'password_salt' in item:
            standardized['passwordSalt'] = item['password_salt']
        
        return standardized
    
    def standardize_project_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize a project item to camelCase schema."""
        now = datetime.utcnow().isoformat()
        
        standardized = {
            'id': item.get('id', str(uuid.uuid4())),
            'name': item.get('name', ''),
            'description': item.get('description', ''),
            'startDate': item.get('startDate') or item.get('start_date', ''),
            'endDate': item.get('endDate') or item.get('end_date', ''),
            'maxParticipants': item.get('maxParticipants') or item.get('max_participants', 0),
            'currentParticipants': item.get('currentParticipants') or item.get('current_participants', 0),
            'status': item.get('status', 'pending'),
            'createdBy': item.get('createdBy') or item.get('created_by', 'system'),
            'createdAt': item.get('createdAt') or item.get('created_at', now),
            'updatedAt': item.get('updatedAt') or item.get('updated_at', now)
        }
        
        # Optional fields
        if 'category' in item:
            standardized['category'] = item['category']
        
        if 'location' in item:
            standardized['location'] = item['location']
        
        if 'requirements' in item:
            standardized['requirements'] = item['requirements']
        
        return standardized
    
    def standardize_subscription_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Standardize a subscription item to camelCase schema."""
        now = datetime.utcnow().isoformat()
        
        standardized = {
            'id': item.get('id', str(uuid.uuid4())),
            'personId': item.get('personId') or item.get('person_id', ''),
            'projectId': item.get('projectId') or item.get('project_id', ''),
            'status': item.get('status', 'active'),
            'subscribedAt': item.get('subscribedAt') or item.get('subscribed_at', now),
            'createdAt': item.get('createdAt') or item.get('created_at', now),
            'updatedAt': item.get('updatedAt') or item.get('updated_at', now)
        }
        
        # Optional fields
        if 'subscribedBy' in item or 'subscribed_by' in item:
            standardized['subscribedBy'] = item.get('subscribedBy') or item.get('subscribed_by')
        
        if 'personName' in item or 'person_name' in item:
            standardized['personName'] = item.get('personName') or item.get('person_name')
        
        if 'personEmail' in item or 'person_email' in item:
            standardized['personEmail'] = item.get('personEmail') or item.get('person_email')
        
        if 'projectName' in item or 'project_name' in item:
            standardized['projectName'] = item.get('projectName') or item.get('project_name')
        
        if 'emailSent' in item or 'email_sent' in item:
            standardized['emailSent'] = item.get('emailSent') or item.get('email_sent', False)
        
        if 'version' in item:
            standardized['version'] = item['version']
        
        return standardized
    
    def item_exists(self, table, item_id: str) -> bool:
        """Check if an item already exists in the table."""
        try:
            response = table.get_item(Key={'id': item_id})
            return 'Item' in response
        except ClientError:
            return False
    
    def print_migration_summary(self):
        """Print migration summary."""
        print("\n" + "=" * 60)
        print("📋 DATA MIGRATION SUMMARY")
        print("=" * 60)
        
        total_migrated = sum(stats['migrated'] for stats in self.migration_stats.values())
        total_errors = sum(stats['errors'] for stats in self.migration_stats.values())
        total_skipped = sum(stats['skipped'] for stats in self.migration_stats.values())
        
        print(f"✅ Total Migrated: {total_migrated}")
        print(f"⚠️  Total Skipped: {total_skipped}")
        print(f"❌ Total Errors: {total_errors}")
        
        for table_type, stats in self.migration_stats.items():
            print(f"\n🔍 {table_type.upper()}:")
            print(f"   Migrated: {stats['migrated']}")
            print(f"   Skipped: {stats['skipped']}")
            print(f"   Errors: {stats['errors']}")
        
        if self.errors:
            print(f"\n❌ ERRORS ENCOUNTERED:")
            for error in self.errors[:10]:  # Show first 10 errors
                print(f"   • {error}")
            if len(self.errors) > 10:
                print(f"   ... and {len(self.errors) - 10} more errors")
        
        if total_errors == 0:
            print("\n🎉 Migration completed successfully with no errors!")
        else:
            print(f"\n⚠️  Migration completed with {total_errors} errors. Please review the errors above.")
    
    def save_migration_report(self, filename: str = None):
        """Save migration report to a JSON file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"migration_report_{timestamp}.json"
        
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'migration_stats': self.migration_stats,
            'errors': self.errors,
            'table_mappings': self.table_mappings
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n💾 Migration report saved to: {filename}")


def main():
    """Main function to run data migration."""
    try:
        migrator = DataMigrator()
        
        # Run migration
        results = migrator.migrate_all_data()
        
        # Save migration report
        migrator.save_migration_report()
        
        # Return exit code based on results
        total_errors = sum(stats['errors'] for stats in results.values())
        if total_errors == 0:
            print("\n🎉 Data migration completed successfully!")
            return 0
        else:
            print(f"\n⚠️  Data migration completed with {total_errors} errors")
            return 1
            
    except Exception as e:
        print(f"\n❌ Error during migration: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())