#!/usr/bin/env python3
"""
Assessment Script: V2 Database Deployment Status
Checks current deployment status of V2 standardized tables and API configuration.
"""

import boto3
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class V2DeploymentAssessment:
    """Assesses current V2 database deployment status."""
    
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.dynamodb = boto3.client('dynamodb', region_name=region)
        self.lambda_client = boto3.client('lambda', region_name=region)
        self.assessment_results = {}
        
    def check_table_exists(self, table_name: str) -> Dict[str, Any]:
        """Check if a DynamoDB table exists and get its details."""
        try:
            response = self.dynamodb.describe_table(TableName=table_name)
            table_info = response['Table']
            
            return {
                'exists': True,
                'status': table_info['TableStatus'],
                'item_count': table_info.get('ItemCount', 0),
                'table_size_bytes': table_info.get('TableSizeBytes', 0),
                'creation_date': table_info['CreationDateTime'].isoformat(),
                'billing_mode': table_info.get('BillingModeSummary', {}).get('BillingMode', 'UNKNOWN'),
                'global_secondary_indexes': [
                    {
                        'name': gsi['IndexName'],
                        'status': gsi['IndexStatus'],
                        'item_count': gsi.get('ItemCount', 0)
                    }
                    for gsi in table_info.get('GlobalSecondaryIndexes', [])
                ]
            }
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return {'exists': False, 'error': 'Table not found'}
            else:
                return {'exists': False, 'error': str(e)}
    
    def assess_dynamodb_tables(self) -> Dict[str, Any]:
        """Assess all V2 and legacy DynamoDB tables."""
        logger.info("🔍 Assessing DynamoDB tables...")
        
        tables_to_check = {
            'v2_tables': {
                'PeopleTableV2': 'Standardized people table',
                'ProjectsTableV2': 'Standardized projects table', 
                'SubscriptionsTableV2': 'Standardized subscriptions table'
            },
            'legacy_tables': {
                'PeopleTable': 'Legacy people table',
                'ProjectsTable': 'Legacy projects table',
                'SubscriptionsTable': 'Legacy subscriptions table'
            }
        }
        
        results = {}
        
        for category, tables in tables_to_check.items():
            results[category] = {}
            for table_name, description in tables.items():
                logger.info(f"  Checking {table_name}...")
                table_info = self.check_table_exists(table_name)
                results[category][table_name] = {
                    'description': description,
                    **table_info
                }
        
        return results 
   
    def get_lambda_functions(self) -> List[Dict[str, Any]]:
        """Get all Lambda functions that might be related to the People Registry."""
        try:
            response = self.lambda_client.list_functions()
            functions = response.get('Functions', [])
            
            # Filter for People Registry related functions
            registry_functions = []
            for func in functions:
                func_name = func['FunctionName']
                if any(keyword in func_name.lower() for keyword in ['people', 'register', 'api', 'auth']):
                    registry_functions.append({
                        'name': func_name,
                        'runtime': func.get('Runtime', 'Unknown'),
                        'handler': func.get('Handler', 'Unknown'),
                        'last_modified': func.get('LastModified', 'Unknown'),
                        'memory_size': func.get('MemorySize', 0),
                        'timeout': func.get('Timeout', 0)
                    })
            
            return registry_functions
        except ClientError as e:
            logger.error(f"Error listing Lambda functions: {e}")
            return []
    
    def check_lambda_environment_variables(self, function_name: str) -> Dict[str, Any]:
        """Check Lambda function environment variables."""
        try:
            response = self.lambda_client.get_function_configuration(FunctionName=function_name)
            env_vars = response.get('Environment', {}).get('Variables', {})
            
            # Check for V2 table environment variables
            v2_vars = {k: v for k, v in env_vars.items() if 'V2' in k}
            legacy_vars = {k: v for k, v in env_vars.items() if k.endswith('_TABLE_NAME') and 'V2' not in k}
            
            return {
                'total_env_vars': len(env_vars),
                'v2_table_vars': v2_vars,
                'legacy_table_vars': legacy_vars,
                'has_v2_config': len(v2_vars) > 0,
                'has_legacy_config': len(legacy_vars) > 0
            }
        except ClientError as e:
            logger.error(f"Error getting Lambda configuration for {function_name}: {e}")
            return {'error': str(e)}
    
    def assess_lambda_functions(self) -> Dict[str, Any]:
        """Assess Lambda function configurations."""
        logger.info("🔍 Assessing Lambda functions...")
        
        functions = self.get_lambda_functions()
        results = {}
        
        for func in functions:
            func_name = func['name']
            logger.info(f"  Checking {func_name}...")
            
            env_assessment = self.check_lambda_environment_variables(func_name)
            results[func_name] = {
                **func,
                'environment_assessment': env_assessment
            }
        
        return results
    
    def assess_api_endpoints(self) -> Dict[str, Any]:
        """Assess API endpoint availability (basic check)."""
        logger.info("🔍 Assessing API endpoints...")
        
        # This is a basic assessment - in production you'd want to make actual HTTP requests
        # For now, we'll just document what should be checked
        
        endpoints_to_check = [
            '/v2/people',
            '/v2/projects', 
            '/v2/subscriptions',
            '/v2/admin/dashboard',
            '/health'
        ]
        
        return {
            'endpoints_to_verify': endpoints_to_check,
            'note': 'Manual verification required - check API Gateway and test endpoints',
            'expected_behavior': 'All endpoints should return camelCase fields consistently'
        }
    
    def generate_deployment_recommendation(self) -> Dict[str, Any]:
        """Generate deployment recommendation based on assessment."""
        tables = self.assessment_results.get('dynamodb_tables', {})
        lambdas = self.assessment_results.get('lambda_functions', {})
        
        v2_tables = tables.get('v2_tables', {})
        legacy_tables = tables.get('legacy_tables', {})
        
        # Check if V2 tables exist
        v2_tables_exist = all(table.get('exists', False) for table in v2_tables.values())
        legacy_tables_exist = all(table.get('exists', False) for table in legacy_tables.values())
        
        # Check if Lambda functions have V2 configuration
        lambda_has_v2_config = any(
            func.get('environment_assessment', {}).get('has_v2_config', False) 
            for func in lambdas.values()
        )
        
        if v2_tables_exist and lambda_has_v2_config:
            recommendation = {
                'status': 'DEPLOYED',
                'action': 'VERIFY_AND_TEST',
                'description': 'V2 tables exist and Lambda functions are configured. Verify data migration and test endpoints.',
                'next_steps': [
                    'Test API endpoints to ensure they work with V2 tables',
                    'Verify data exists in V2 tables',
                    'Check API responses use camelCase fields',
                    'Monitor for any errors or performance issues'
                ]
            }
        elif v2_tables_exist and not lambda_has_v2_config:
            recommendation = {
                'status': 'PARTIALLY_DEPLOYED',
                'action': 'UPDATE_LAMBDA_CONFIG',
                'description': 'V2 tables exist but Lambda functions not configured to use them.',
                'next_steps': [
                    'Deploy CDK stack to update Lambda environment variables',
                    'Test API endpoints after Lambda update',
                    'Migrate data from legacy to V2 tables if needed'
                ]
            }
        elif not v2_tables_exist and legacy_tables_exist:
            recommendation = {
                'status': 'NOT_DEPLOYED',
                'action': 'DEPLOY_V2_TABLES',
                'description': 'V2 tables do not exist. Need to deploy through CDK pipeline.',
                'next_steps': [
                    'Create feature branch for V2 table deployment',
                    'Deploy CDK stack to create V2 tables',
                    'Update Lambda environment variables',
                    'Migrate data from legacy to V2 tables',
                    'Test and verify API functionality'
                ]
            }
        else:
            recommendation = {
                'status': 'UNKNOWN',
                'action': 'INVESTIGATE',
                'description': 'Unexpected state - neither V2 nor legacy tables found.',
                'next_steps': [
                    'Check AWS region and credentials',
                    'Verify table names and CDK configuration',
                    'Review deployment history'
                ]
            }
        
        return recommendation  
  
    def run_complete_assessment(self) -> Dict[str, Any]:
        """Run complete V2 deployment assessment."""
        logger.info("🚀 Starting V2 Database Deployment Assessment")
        
        # Assess DynamoDB tables
        self.assessment_results['dynamodb_tables'] = self.assess_dynamodb_tables()
        
        # Assess Lambda functions
        self.assessment_results['lambda_functions'] = self.assess_lambda_functions()
        
        # Assess API endpoints
        self.assessment_results['api_endpoints'] = self.assess_api_endpoints()
        
        # Generate recommendation
        self.assessment_results['recommendation'] = self.generate_deployment_recommendation()
        
        # Add metadata
        self.assessment_results['assessment_metadata'] = {
            'timestamp': datetime.utcnow().isoformat(),
            'region': self.region,
            'assessor': 'V2DeploymentAssessment'
        }
        
        return self.assessment_results
    
    def print_summary(self):
        """Print a human-readable summary of the assessment."""
        results = self.assessment_results
        
        print("\n" + "="*60)
        print("🔍 V2 DATABASE DEPLOYMENT ASSESSMENT SUMMARY")
        print("="*60)
        
        # DynamoDB Tables Summary
        print("\n📊 DYNAMODB TABLES:")
        tables = results.get('dynamodb_tables', {})
        
        for category, table_group in tables.items():
            print(f"\n  {category.upper().replace('_', ' ')}:")
            for table_name, table_info in table_group.items():
                status = "✅ EXISTS" if table_info.get('exists') else "❌ NOT FOUND"
                item_count = table_info.get('item_count', 0)
                print(f"    {table_name}: {status} ({item_count} items)")
        
        # Lambda Functions Summary
        print("\n🔧 LAMBDA FUNCTIONS:")
        functions = results.get('lambda_functions', {})
        for func_name, func_info in functions.items():
            env_assessment = func_info.get('environment_assessment', {})
            v2_config = "✅ HAS V2 CONFIG" if env_assessment.get('has_v2_config') else "❌ NO V2 CONFIG"
            print(f"    {func_name}: {v2_config}")
        
        # Recommendation
        print("\n🎯 RECOMMENDATION:")
        recommendation = results.get('recommendation', {})
        print(f"    Status: {recommendation.get('status', 'UNKNOWN')}")
        print(f"    Action: {recommendation.get('action', 'UNKNOWN')}")
        print(f"    Description: {recommendation.get('description', 'No description')}")
        
        print("\n📋 NEXT STEPS:")
        for i, step in enumerate(recommendation.get('next_steps', []), 1):
            print(f"    {i}. {step}")
        
        print("\n" + "="*60)

def main():
    """Main assessment execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Assess V2 Database Deployment Status')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--output', help='Output file for detailed results (JSON)')
    parser.add_argument('--summary-only', action='store_true', help='Show only summary')
    
    args = parser.parse_args()
    
    # Run assessment
    assessor = V2DeploymentAssessment(region=args.region)
    results = assessor.run_complete_assessment()
    
    # Print summary
    assessor.print_summary()
    
    # Save detailed results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"📄 Detailed results saved to: {args.output}")
    
    # Exit with appropriate code based on recommendation
    recommendation = results.get('recommendation', {})
    status = recommendation.get('status', 'UNKNOWN')
    
    if status == 'DEPLOYED':
        logger.info("✅ V2 deployment appears to be complete!")
        exit(0)
    elif status in ['PARTIALLY_DEPLOYED', 'NOT_DEPLOYED']:
        logger.info("⚠️  V2 deployment needs attention.")
        exit(1)
    else:
        logger.error("❌ Unable to determine deployment status.")
        exit(2)

if __name__ == "__main__":
    main()