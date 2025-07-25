# PR Validation Workflow Troubleshooting Guide

This guide helps developers and teams troubleshoot common issues with the pull request validation workflow.

## Quick Diagnosis

### Check Validation Status

1. **Navigate to Pull Request**: Go to your pull request in CodeCatalyst
2. **Check Status**: Look for workflow status indicators
3. **View Details**: Click on failed checks for detailed logs
4. **Review Artifacts**: Download artifacts for detailed analysis

### Common Status Indicators

- ✅ **All checks passed**: Validation successful, ready for review
- ❌ **Some checks failed**: Validation issues need attention
- 🟡 **Checks in progress**: Validation running, wait for completion
- ⚪ **No status**: Workflow may not have triggered

## Common Validation Failures

### 1. CDK Synthesis Failures

#### Symptoms
```
Error: CDK synthesis failed
Template validation errors found
CloudFormation template generation failed
```

#### Common Causes
- **Invalid Resource Configuration**: Incorrect resource properties or types
- **Missing Dependencies**: Required CDK constructs not imported
- **Circular Dependencies**: Resources referencing each other incorrectly
- **Invalid Parameter Values**: Parameters outside allowed ranges or formats

#### Solutions

**Check Resource Configuration**:
```bash
# Run local CDK synthesis to identify issues
cd registry-infrastructure
cdk synth

# Check for specific resource errors
cdk synth --verbose
```

**Validate CDK Code**:
```python
# Common issues in CDK code
# 1. Missing imports
from aws_cdk import aws_lambda as _lambda

# 2. Incorrect resource properties
lambda_function = _lambda.Function(
    self, "MyFunction",
    runtime=_lambda.Runtime.PYTHON_3_9,  # Correct runtime
    handler="index.handler",
    code=_lambda.Code.from_asset("lambda")
)

# 3. Proper dependency management
table = dynamodb.Table(...)
lambda_function.add_environment("TABLE_NAME", table.table_name)
table.grant_read_write_data(lambda_function)
```

**Fix Common CDK Issues**:
- Verify all imports are correct
- Check resource property names and values
- Ensure proper dependency relationships
- Validate parameter constraints

### 2. IAM Permission Validation Failures

#### Symptoms
```
Error: IAM permission validation failed
Insufficient permissions for resource access
Policy validation errors
```

#### Common Causes
- **Overly Restrictive Policies**: Policies too restrictive for required operations
- **Missing Permissions**: Required permissions not granted
- **Invalid Policy Syntax**: JSON syntax errors in policy documents
- **Resource ARN Mismatches**: Incorrect resource ARNs in policies

#### Solutions

**Review IAM Policies**:
```python
# Example: Proper Lambda execution role
lambda_role = iam.Role(
    self, "LambdaExecutionRole",
    assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
    managed_policies=[
        iam.ManagedPolicy.from_aws_managed_policy_name(
            "service-role/AWSLambdaBasicExecutionRole"
        )
    ]
)

# Add specific permissions
lambda_role.add_to_policy(iam.PolicyStatement(
    effect=iam.Effect.ALLOW,
    actions=["dynamodb:GetItem", "dynamodb:PutItem"],
    resources=[table.table_arn]
))
```

**Validate Policy Syntax**:
- Use AWS Policy Simulator for testing
- Validate JSON syntax in policy documents
- Check resource ARN formats
- Verify action names and resource types

### 3. API Integration Validation Failures

#### Symptoms
```
Error: API integration validation failed
Handler configuration errors
Dependency compatibility issues
```

#### Common Causes
- **Missing Dependencies**: Required Python packages not in requirements.txt
- **Version Conflicts**: Incompatible package versions
- **Handler Configuration**: Incorrect handler setup or imports
- **Environment Variables**: Missing or incorrect environment variable configuration

#### Solutions

**Check Dependencies**:
```bash
# Verify requirements.txt
cd registry-infrastructure/lambda
pip install -r requirements.txt

# Check for conflicts
pip check

# Update dependencies if needed
pip freeze > requirements.txt
```

**Validate Handler Configuration**:
```python
# Example: Proper handler setup
import json
from mangum import Mangum
from main import app  # FastAPI app

# Ensure proper ASGI adapter
handler = Mangum(app, lifespan="off")

def lambda_handler(event, context):
    return handler(event, context)
```

**Environment Variable Validation**:
```python
import os

# Check required environment variables
required_vars = [
    "PEOPLE_TABLE_NAME",
    "JWT_SECRET",
    "FRONTEND_URL"
]

for var in required_vars:
    if not os.getenv(var):
        raise ValueError(f"Missing required environment variable: {var}")
```

### 4. Resource Configuration Validation Failures

#### Symptoms
```
Error: Resource configuration validation failed
Invalid resource properties
Resource limit exceeded
```

#### Common Causes
- **Invalid Property Values**: Properties outside allowed ranges
- **Resource Limits**: Exceeding AWS service limits
- **Naming Conflicts**: Resource names conflicting with existing resources
- **Region Restrictions**: Resources not available in target region

#### Solutions

**Validate Resource Properties**:
```python
# Example: Proper DynamoDB table configuration
table = dynamodb.Table(
    self, "PeopleTable",
    table_name="PeopleTable",
    partition_key=dynamodb.Attribute(
        name="id",
        type=dynamodb.AttributeType.STRING
    ),
    billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
    removal_policy=RemovalPolicy.RETAIN  # For production
)
```

**Check Service Limits**:
- Review AWS service quotas
- Verify resource counts within limits
- Check region-specific restrictions
- Consider resource optimization

### 5. Template Validation Failures

#### Symptoms
```
Error: CloudFormation template validation failed
Template format errors
Invalid template structure
```

#### Common Causes
- **Template Size**: Template exceeds size limits
- **Invalid References**: Incorrect resource references
- **Circular Dependencies**: Resources creating circular references
- **Invalid Outputs**: Output definitions with errors

#### Solutions

**Validate Template Structure**:
```bash
# Use AWS CLI to validate template
aws cloudformation validate-template --template-body file://template.json

# Check template size
ls -lh cdk.out/*.template.json
```

**Fix Common Template Issues**:
- Reduce template size by splitting stacks
- Verify all resource references
- Check output definitions
- Validate parameter usage

## Debugging Workflow Issues

### 1. Workflow Not Triggering

#### Check Trigger Configuration
```yaml
# Verify trigger configuration in workflow file
Triggers:
  - Type: PULLREQUEST
    Branches:
      - main
    Events:
      - PULLREQUEST_CREATED
      - PULLREQUEST_REVISION_CREATED
```

#### Verify Pull Request Target
- Ensure PR targets the main branch
- Check that PR is not in draft mode
- Verify repository permissions

### 2. Execution Mode Detection Issues

#### Check Environment Variables
```bash
# Debug execution mode detection
echo "Trigger Type: $CODECATALYST_TRIGGER_TYPE"
echo "Source Branch: $CODECATALYST_SOURCE_BRANCH_NAME"
echo "Target Branch: $CODECATALYST_TARGET_BRANCH_NAME"
```

#### Verify Mode Logic
```bash
# Execution mode determination logic
if [ "$CODECATALYST_TRIGGER_TYPE" = "PULLREQUEST" ]; then
    echo "Execution Mode: validation"
else
    echo "Execution Mode: deployment"
fi
```

### 3. Artifact Generation Issues

#### Check Artifact Structure
```bash
# Verify artifact creation
ls -la artifacts/
cat artifacts/validation-summary.json
```

#### Validate Artifact Content
```json
{
  "execution_mode": "validation",
  "timestamp": "2025-07-25T10:30:00Z",
  "stages_executed": ["CheckAPISync", "PrepareAPIIntegration", "ValidateInfrastructure"],
  "validation_results": {
    "status": "success"
  }
}
```

## Performance Issues

### 1. Slow Validation Times

#### Identify Bottlenecks
- Check CDK synthesis time
- Review dependency installation time
- Monitor resource validation duration

#### Optimization Strategies
```bash
# Use dependency caching
pip install --cache-dir /tmp/pip-cache -r requirements.txt

# Parallel validation where possible
cdk synth --parallel

# Skip unnecessary validations
if [ "$EXECUTION_MODE" = "validation" ]; then
    echo "Skipping deployment-specific validations"
fi
```

### 2. Resource Constraints

#### Monitor Resource Usage
- Check memory usage during validation
- Monitor CPU utilization
- Review disk space requirements

#### Resource Optimization
- Reduce validation scope for PRs
- Use smaller instance types for validation
- Implement validation caching

## Error Message Reference

### Common Error Patterns

| Error Pattern | Likely Cause | Solution |
|---------------|--------------|----------|
| `CDK synthesis failed` | Invalid CDK code | Review CDK configuration |
| `IAM permission denied` | Missing permissions | Update IAM policies |
| `Template validation failed` | CloudFormation errors | Validate template syntax |
| `Handler import error` | Missing dependencies | Update requirements.txt |
| `Environment variable missing` | Configuration error | Set required variables |
| `Resource limit exceeded` | AWS service limits | Review resource usage |

### Error Code Mapping

- **E001**: CDK synthesis failure
- **E002**: IAM permission validation failure
- **E003**: API integration validation failure
- **E004**: Resource configuration validation failure
- **E005**: Template validation failure
- **E006**: Artifact generation failure

## Getting Help

### Self-Service Resources

1. **Check Logs**: Review detailed workflow logs in CodeCatalyst
2. **Validate Locally**: Run CDK commands locally to reproduce issues
3. **Review Documentation**: Check related documentation for guidance
4. **Search Issues**: Look for similar issues in team knowledge base

### Escalation Process

1. **Team Lead**: Contact team lead for workflow-related issues
2. **DevOps Team**: Escalate infrastructure and deployment issues
3. **Platform Team**: Contact for CodeCatalyst platform issues
4. **AWS Support**: For AWS service-specific problems

### Information to Provide

When seeking help, include:

- **Pull Request URL**: Link to the failing pull request
- **Workflow Run ID**: CodeCatalyst workflow execution ID
- **Error Messages**: Complete error messages and stack traces
- **Environment Details**: Branch, trigger type, execution mode
- **Recent Changes**: What changes were made that might cause the issue

## Prevention Strategies

### Development Best Practices

1. **Local Validation**: Always run `cdk synth` locally before creating PR
2. **Small Changes**: Keep pull requests small and focused
3. **Test Dependencies**: Verify all dependencies are properly specified
4. **Documentation**: Keep configuration documentation up to date

### Team Processes

1. **Code Reviews**: Include validation configuration in code reviews
2. **Knowledge Sharing**: Share common issues and solutions with team
3. **Monitoring**: Monitor validation success rates and common failures
4. **Continuous Improvement**: Regularly update validation processes

### Automation

1. **Pre-commit Hooks**: Add local validation to pre-commit hooks
2. **IDE Integration**: Use IDE plugins for CDK validation
3. **Automated Testing**: Include validation tests in development workflow
4. **Monitoring Alerts**: Set up alerts for validation failure patterns

---

**Last Updated**: July 25, 2025

For additional help, see:
- [PR Validation Workflow Documentation](pr-validation-workflow.md)
- [Team Process Guidelines](../team-processes/pr-validation-process.md)
- [Infrastructure Deployment Guide](infrastructure-deployment.md)