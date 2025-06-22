import boto3
import json

# Create a boto3 client for CodeCatalyst
client = boto3.client('codecatalyst', region_name='us-east-1')

try:
    # Get workflow runs
    response = client.list_workflow_runs(
        spaceName='AWSCocha',
        projectName='people-registry',
        workflowId='Deploy_Infrastructure'
    )
    print(json.dumps(response, indent=2))
except Exception as e:
    print(f"Error: {str(e)}")
