#!/usr/bin/env python3
"""
Database Schema Audit Script
Analyzes current DynamoDB tables to identify field inconsistencies and prepare for standardization.
"""

import boto3
import json
from typing import Dict, List, Any, Set
from collections import defaultdict, Counter
import sys
from datetime import datetime


class DatabaseSchemaAuditor:
    """Audits DynamoDB tables for schema inconsistencies."""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.tables = {
            'people': 'PeopleTable',
            'projects': 'ProjectsTable', 
            'subscriptions': 'SubscriptionsTable'
        }
        self.audit_results = {}
    
    def audit_all_tables(self) -> Dict[str, Any]:
        """Audit all tables and return comprehensive results."""
        print("🔍 Starting Database Schema Audit...")
        print("=" * 60)
        
        for table_type, table_name in self.tables.items():
            print(f"\n📊 Auditing {table_type.upper()} table ({table_name})...")
            try:
                self.audit_results[table_type] = self.audit_table(table_name)
                print(f"✅ {table_type.upper()} audit completed")
            except Exception as e:
                print(f"❌ Error auditing {table_type}: {str(e)}")
                self.audit_results[table_type] = {"error": str(e)}
        
        # Generate summary report
        self.generate_summary_report()
        return self.audit_results
    
    def audit_table(self, table_name: str) -> Dict[str, Any]:
        """Audit a specific table for schema inconsistencies."""
        table = self.dynamodb.Table(table_name)
        
        # Scan table to get all items
        response = table.scan()
        items = response['Items']
        
        # Continue scanning if there are more items
        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            items.extend(response['Items'])
        
        print(f"   📈 Found {len(items)} items")
        
        if not items:
            return {
                "item_count": 0,
                "field_analysis": {},
                "issues": ["Table is empty"]
            }
        
        # Analyze field patterns
        field_analysis = self.analyze_fields(items)
        
        # Identify issues
        issues = self.identify_issues(field_analysis, table_name)
        
        return {
            "item_count": len(items),
            "field_analysis": field_analysis,
            "issues": issues,
            "sample_items": items[:3] if items else []  # First 3 items as samples
        }
    
    def analyze_fields(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze field patterns across all items."""
        all_fields = set()
        field_types = defaultdict(Counter)
        field_presence = defaultdict(int)
        nested_fields = defaultdict(set)
        
        for item in items:
            self._analyze_item_fields(item, all_fields, field_types, field_presence, nested_fields)
        
        total_items = len(items)
        
        return {
            "total_fields": len(all_fields),
            "all_fields": sorted(list(all_fields)),
            "field_presence": {
                field: {
                    "count": count,
                    "percentage": round((count / total_items) * 100, 2)
                }
                for field, count in field_presence.items()
            },
            "field_types": dict(field_types),
            "nested_fields": {k: list(v) for k, v in nested_fields.items()},
            "total_items": total_items
        }
    
    def _analyze_item_fields(self, item: Dict[str, Any], all_fields: Set[str], 
                           field_types: defaultdict, field_presence: defaultdict, 
                           nested_fields: defaultdict, prefix: str = ""):
        """Recursively analyze fields in an item."""
        for field, value in item.items():
            full_field = f"{prefix}.{field}" if prefix else field
            all_fields.add(full_field)
            field_presence[full_field] += 1
            
            # Determine field type
            if isinstance(value, dict):
                field_types[full_field]['dict'] += 1
                nested_fields[full_field].update(value.keys())
                # Recursively analyze nested fields
                self._analyze_item_fields(value, all_fields, field_types, field_presence, nested_fields, full_field)
            elif isinstance(value, list):
                field_types[full_field]['list'] += 1
                if value and isinstance(value[0], dict):
                    # Analyze first item in list if it's a dict
                    self._analyze_item_fields(value[0], all_fields, field_types, field_presence, nested_fields, f"{full_field}[0]")
            elif isinstance(value, str):
                field_types[full_field]['string'] += 1
            elif isinstance(value, (int, float)):
                field_types[full_field]['number'] += 1
            elif isinstance(value, bool):
                field_types[full_field]['boolean'] += 1
            else:
                field_types[full_field]['other'] += 1
    
    def identify_issues(self, field_analysis: Dict[str, Any], table_name: str) -> List[str]:
        """Identify schema issues based on field analysis."""
        issues = []
        field_presence = field_analysis["field_presence"]
        total_items = field_analysis["total_items"]
        
        # Check for inconsistent field presence
        for field, presence_info in field_presence.items():
            percentage = presence_info["percentage"]
            if percentage < 100 and percentage > 0:
                issues.append(f"Field '{field}' is missing in {100 - percentage:.1f}% of items")
        
        # Check for naming convention issues
        snake_case_fields = [f for f in field_analysis["all_fields"] if '_' in f]
        camel_case_fields = [f for f in field_analysis["all_fields"] if any(c.isupper() for c in f)]
        
        if snake_case_fields and camel_case_fields:
            issues.append(f"Mixed naming conventions: {len(snake_case_fields)} snake_case, {len(camel_case_fields)} camelCase fields")
        
        # Table-specific checks
        if table_name == "PeopleTable":
            self._check_people_table_issues(field_analysis, issues)
        elif table_name == "ProjectsTable":
            self._check_projects_table_issues(field_analysis, issues)
        elif table_name == "SubscriptionsTable":
            self._check_subscriptions_table_issues(field_analysis, issues)
        
        return issues
    
    def _check_people_table_issues(self, field_analysis: Dict[str, Any], issues: List[str]):
        """Check for people table specific issues."""
        required_fields = ['id', 'email', 'firstName', 'lastName']
        all_fields = field_analysis["all_fields"]
        field_presence = field_analysis["field_presence"]
        
        for field in required_fields:
            if field not in all_fields:
                # Check for snake_case version
                snake_field = self._to_snake_case(field)
                if snake_field in all_fields:
                    issues.append(f"Required field '{field}' found as '{snake_field}' (naming inconsistency)")
                else:
                    issues.append(f"Required field '{field}' is missing")
            elif field_presence[field]["percentage"] < 100:
                issues.append(f"Required field '{field}' is missing in some items")
        
        # Check address structure
        if 'address' in all_fields:
            nested_fields = field_analysis["nested_fields"].get('address', set())
            required_address_fields = ['street', 'city', 'state', 'postalCode', 'country']
            for addr_field in required_address_fields:
                if addr_field not in nested_fields:
                    snake_addr_field = self._to_snake_case(addr_field)
                    if snake_addr_field in nested_fields:
                        issues.append(f"Address field '{addr_field}' found as '{snake_addr_field}' (naming inconsistency)")
                    else:
                        issues.append(f"Address field '{addr_field}' is missing")
    
    def _check_projects_table_issues(self, field_analysis: Dict[str, Any], issues: List[str]):
        """Check for projects table specific issues."""
        required_fields = ['id', 'name', 'description', 'startDate', 'endDate', 'maxParticipants']
        all_fields = field_analysis["all_fields"]
        
        for field in required_fields:
            if field not in all_fields:
                snake_field = self._to_snake_case(field)
                if snake_field in all_fields:
                    issues.append(f"Required field '{field}' found as '{snake_field}' (naming inconsistency)")
                else:
                    issues.append(f"Required field '{field}' is missing")
    
    def _check_subscriptions_table_issues(self, field_analysis: Dict[str, Any], issues: List[str]):
        """Check for subscriptions table specific issues."""
        required_fields = ['id', 'personId', 'projectId', 'status']
        all_fields = field_analysis["all_fields"]
        
        for field in required_fields:
            if field not in all_fields:
                snake_field = self._to_snake_case(field)
                if snake_field in all_fields:
                    issues.append(f"Required field '{field}' found as '{snake_field}' (naming inconsistency)")
                else:
                    issues.append(f"Required field '{field}' is missing")
    
    def _to_snake_case(self, camel_str: str) -> str:
        """Convert camelCase to snake_case."""
        result = []
        for i, char in enumerate(camel_str):
            if char.isupper() and i > 0:
                result.append('_')
            result.append(char.lower())
        return ''.join(result)
    
    def generate_summary_report(self):
        """Generate a comprehensive summary report."""
        print("\n" + "=" * 60)
        print("📋 DATABASE SCHEMA AUDIT SUMMARY")
        print("=" * 60)
        
        total_items = sum(
            result.get("item_count", 0) 
            for result in self.audit_results.values() 
            if isinstance(result, dict) and "item_count" in result
        )
        
        total_issues = sum(
            len(result.get("issues", [])) 
            for result in self.audit_results.values() 
            if isinstance(result, dict) and "issues" in result
        )
        
        print(f"📊 Total Items Analyzed: {total_items}")
        print(f"⚠️  Total Issues Found: {total_issues}")
        
        for table_type, result in self.audit_results.items():
            if isinstance(result, dict) and "error" not in result:
                print(f"\n🔍 {table_type.upper()} TABLE:")
                print(f"   Items: {result['item_count']}")
                print(f"   Fields: {result['field_analysis']['total_fields']}")
                print(f"   Issues: {len(result['issues'])}")
                
                if result['issues']:
                    print("   ⚠️  Issues found:")
                    for issue in result['issues']:
                        print(f"      • {issue}")
        
        # Generate recommendations
        self.generate_recommendations()
    
    def generate_recommendations(self):
        """Generate recommendations for database standardization."""
        print("\n" + "=" * 60)
        print("💡 RECOMMENDATIONS")
        print("=" * 60)
        
        has_naming_issues = any(
            "naming inconsistency" in issue or "Mixed naming conventions" in issue
            for result in self.audit_results.values()
            if isinstance(result, dict) and "issues" in result
            for issue in result["issues"]
        )
        
        has_missing_fields = any(
            "missing" in issue and "naming inconsistency" not in issue
            for result in self.audit_results.values()
            if isinstance(result, dict) and "issues" in result
            for issue in result["issues"]
        )
        
        print("🎯 PRIORITY 1: Database Schema Standardization")
        
        if has_naming_issues:
            print("   ✅ Create new standardized tables with camelCase fields")
            print("   ✅ Implement data migration scripts")
            print("   ✅ Use blue-green deployment strategy")
        
        if has_missing_fields:
            print("   ✅ Define complete schema with all required fields")
            print("   ✅ Set default values for missing fields during migration")
        
        print("\n🔧 IMPLEMENTATION STEPS:")
        print("   1. Create new DynamoDB tables with standardized schema")
        print("   2. Implement data migration scripts")
        print("   3. Update API to use new tables")
        print("   4. Test thoroughly with new schema")
        print("   5. Deploy with rollback capability")
        
        print("\n📋 SCHEMA DESIGN PRINCIPLES:")
        print("   • Consistent camelCase field naming")
        print("   • Complete address structures")
        print("   • Required vs optional field clarity")
        print("   • Proper data types for all fields")
    
    def save_audit_report(self, filename: str = None):
        """Save the audit results to a JSON file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"database_audit_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.audit_results, f, indent=2, default=str)
        
        print(f"\n💾 Audit report saved to: {filename}")


def main():
    """Main function to run the database audit."""
    try:
        auditor = DatabaseSchemaAuditor()
        results = auditor.audit_all_tables()
        
        # Save results to file
        auditor.save_audit_report()
        
        print("\n🎉 Database audit completed successfully!")
        
        # Return exit code based on issues found
        total_issues = sum(
            len(result.get("issues", [])) 
            for result in results.values() 
            if isinstance(result, dict) and "issues" in result
        )
        
        if total_issues > 0:
            print(f"\n⚠️  Found {total_issues} issues that need attention")
            return 1
        else:
            print("\n✅ No issues found - database schema is consistent!")
            return 0
            
    except Exception as e:
        print(f"\n❌ Error during audit: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())