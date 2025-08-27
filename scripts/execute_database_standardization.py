#!/usr/bin/env python3
"""
Execute Database Standardization
Complete workflow to standardize the database schema and migrate data.
"""

import sys
import subprocess
from datetime import datetime


def run_command(command: str, description: str) -> bool:
    """Run a command and return success status."""
    print(f"\n🔄 {description}...")
    print(f"   Command: {command}")
    
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        if result.stdout:
            print("   Output:")
            for line in result.stdout.split('\n')[:10]:  # Show first 10 lines
                if line.strip():
                    print(f"   {line}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed")
        print(f"   Error: {e}")
        if e.stdout:
            print("   Output:")
            print(f"   {e.stdout}")
        if e.stderr:
            print("   Error Output:")
            print(f"   {e.stderr}")
        return False


def main():
    """Execute the complete database standardization workflow."""
    print("🚀 DATABASE STANDARDIZATION WORKFLOW")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    steps = [
        {
            'command': 'python scripts/audit_database_schema.py',
            'description': 'Audit current database schema',
            'required': False  # Optional - we already know the issues
        },
        {
            'command': 'python scripts/create_standardized_tables.py',
            'description': 'Create standardized DynamoDB tables',
            'required': True
        },
        {
            'command': 'python scripts/migrate_data_to_standardized_tables.py',
            'description': 'Migrate data to standardized tables',
            'required': True
        }
    ]
    
    success_count = 0
    total_required = sum(1 for step in steps if step['required'])
    
    for i, step in enumerate(steps, 1):
        print(f"\n{'='*60}")
        print(f"STEP {i}/{len(steps)}: {step['description'].upper()}")
        print(f"{'='*60}")
        
        success = run_command(step['command'], step['description'])
        
        if success:
            success_count += 1
        elif step['required']:
            print(f"\n❌ CRITICAL FAILURE: {step['description']} is required but failed")
            print("   Stopping workflow to prevent data corruption")
            return 1
        else:
            print(f"\n⚠️  Optional step failed: {step['description']}")
    
    # Final summary
    print(f"\n{'='*60}")
    print("📋 WORKFLOW SUMMARY")
    print(f"{'='*60}")
    print(f"✅ Completed Steps: {success_count}/{len(steps)}")
    print(f"🎯 Required Steps: {success_count}/{total_required}")
    
    if success_count >= total_required:
        print("\n🎉 DATABASE STANDARDIZATION COMPLETED SUCCESSFULLY!")
        print("\n🚀 NEXT STEPS:")
        print("1. ✅ Update API environment variables to use new table names:")
        print("   - PEOPLE_TABLE_NAME=PeopleTableV2")
        print("   - PROJECTS_TABLE_NAME=ProjectsTableV2") 
        print("   - SUBSCRIPTIONS_TABLE_NAME=SubscriptionsTableV2")
        print("2. 🧪 Test API with new standardized tables")
        print("3. 🚀 Deploy API updates")
        print("4. 🗑️  Clean up old tables after successful testing")
        return 0
    else:
        print(f"\n❌ WORKFLOW FAILED: {total_required - success_count} required steps failed")
        print("   Please review the errors above and retry")
        return 1


if __name__ == "__main__":
    sys.exit(main())