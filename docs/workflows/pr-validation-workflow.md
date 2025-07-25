# Pull Request Validation Workflow

This document describes the pull request validation workflow that provides fast feedback on infrastructure changes before they are merged to the main branch.

## Overview

The PR validation workflow runs validation stages when pull requests are created or updated, allowing developers to catch configuration errors, syntax issues, and validation problems before merging code into main. This provides fast feedback (5-10 minutes) compared to full deployment cycles (15-30 minutes).

## Workflow Behavior

### Execution Modes

The workflow operates in two distinct modes based on the trigger type:

#### Validation Mode (Pull Requests)
- **Trigger**: Pull request creation or updates
- **Stages Executed**: CheckAPISync → PrepareAPIIntegration → ValidateInfrastructure
- **Stages Skipped**: DeployInfrastructure, PostDeploymentTests, NotifyDeploymentStatus
- **Duration**: ~5-10 minutes
- **Purpose**: Fast feedback on configuration and validation issues

#### Deployment Mode (Main Branch)
- **Trigger**: Push to main branch
- **Stages Executed**: All stages (full deployment pipeline)
- **Duration**: ~15-30 minutes
- **Purpose**: Complete infrastructure deployment and testing

### Trigger Conditions

The workflow is configured with multiple triggers:

```yaml
Triggers:
  - Type: PUSH
    Branches:
      - main
  - Type: PULLREQUEST
    Branches:
      - main
    Events:
      - PULLREQUEST_CREATED
      - PULLREQUEST_REVISION_CREATED
```

### Execution Mode Detection

The workflow determines execution mode using environment variables:

```bash
# Primary detection method
if [ "$CODECATALYST_TRIGGER_TYPE" = "PULLREQUEST" ]; then
    EXECUTION_MODE="validation"
else
    EXECUTION_MODE="deployment"
fi

# Fallback branch-based detection
if [ "${CODECATALYST_SOURCE_BRANCH_NAME}" != "main" ]; then
    EXECUTION_MODE="validation"
fi
```

## Stage Behavior

### Always Executed Stages

#### CheckAPISync
- **Purpose**: Detects if deployment includes synchronized API code
- **Behavior**: Identical in both validation and deployment modes
- **Output**: API synchronization status and metadata

#### PrepareAPIIntegration
- **Purpose**: Prepares API integration components
- **Behavior**: Identical in both validation and deployment modes
- **Output**: Integration configuration and handlers

#### ValidateInfrastructure
- **Purpose**: Validates infrastructure configuration
- **Enhanced Features**:
  - CDK synthesis validation (`cdk synth`)
  - IAM permission validation
  - Resource configuration validation
  - Template error detection
- **Output**: Validation results and error reports

### Conditionally Executed Stages

#### DeployInfrastructure
- **Validation Mode**: Creates placeholder artifacts, skips actual deployment
- **Deployment Mode**: Performs actual CDK deployment to AWS
- **Placeholder Artifacts**: Maintains expected structure for downstream compatibility

#### PostDeploymentTests
- **Validation Mode**: Creates placeholder test report
- **Deployment Mode**: Runs actual tests against deployed infrastructure
- **Placeholder Content**: Simulated test results for artifact compatibility

#### NotifyDeploymentStatus
- **Validation Mode**: Creates validation summary notification
- **Deployment Mode**: Creates deployment completion notification
- **Content**: Execution mode-specific messaging and results

## Artifact Management

### Validation Mode Artifacts

The workflow creates placeholder artifacts in validation mode to maintain compatibility:

```json
{
  "validation_summary": {
    "timestamp": "2025-07-25T10:30:00Z",
    "execution_mode": "validation",
    "stages_executed": ["CheckAPISync", "PrepareAPIIntegration", "ValidateInfrastructure"],
    "stages_skipped": ["DeployInfrastructure", "PostDeploymentTests"],
    "validation_results": {
      "api_sync_status": "success",
      "integration_status": "success", 
      "infrastructure_status": "success"
    }
  }
}
```

### Artifact Compatibility

- **Structure**: Placeholder artifacts maintain the same structure as deployment artifacts
- **Naming**: Identical naming conventions for both modes
- **Content**: Validation mode includes execution context and placeholder data
- **Downstream**: All expected artifacts are present regardless of execution mode

## Validation Checks

### Infrastructure Validation

The ValidateInfrastructure stage performs comprehensive checks:

1. **CDK Synthesis**: Validates CloudFormation template generation
2. **Resource Configuration**: Checks resource definitions and properties
3. **IAM Permissions**: Validates IAM roles and policies
4. **Dependencies**: Verifies dependency compatibility
5. **Security**: Basic security configuration validation

### API Integration Validation

The PrepareAPIIntegration stage validates:

1. **Handler Configuration**: API handler setup and configuration
2. **Dependency Compatibility**: Python package compatibility
3. **Integration Points**: API Gateway and Lambda integration
4. **Environment Variables**: Required configuration validation

## Status Reporting

### Pull Request Status Checks

The workflow provides status checks on pull requests:

- **Green Check**: All validation stages passed successfully
- **Red X**: One or more validation stages failed
- **Yellow Circle**: Validation in progress
- **Details**: Click for detailed error messages and logs

### Validation Results

Validation results include:

- **Stage Status**: Success/failure for each executed stage
- **Error Details**: Specific error messages and suggested fixes
- **Execution Time**: Duration of validation process
- **Artifact Links**: Links to generated artifacts and logs

## Performance Characteristics

### Validation Mode Performance

- **Target Duration**: 5-10 minutes
- **Optimizations**: 
  - Skip actual deployment operations
  - Use cached dependencies where possible
  - Parallel validation checks
  - Minimal artifact generation

### Resource Usage

- **Compute**: Reduced compute requirements in validation mode
- **Storage**: Minimal artifact storage for placeholders
- **Network**: No AWS deployment operations in validation mode

## Integration with Development Workflow

### Developer Experience

1. **Create Pull Request**: Validation workflow triggers automatically
2. **Fast Feedback**: Results available in 5-10 minutes
3. **Fix Issues**: Address validation failures before review
4. **Merge**: Full deployment runs on main branch after merge

### Code Review Process

1. **Validation Status**: Check validation results before reviewing code
2. **Error Resolution**: Ensure all validation issues are resolved
3. **Approval**: Approve pull request after validation passes
4. **Merge**: Merge triggers full deployment workflow

## Security Considerations

### Validation Mode Security

- **Limited Permissions**: Validation mode uses restricted AWS permissions
- **No Deployment**: No actual infrastructure changes in validation mode
- **Isolation**: Pull request validation isolated from production
- **Audit**: All validation activities are logged and auditable

### Sensitive Information

- **Environment Variables**: Validation mode has access to non-sensitive config only
- **Secrets**: Production secrets not available in validation mode
- **Logs**: Validation logs may contain configuration details but not secrets

## Monitoring and Observability

### Metrics

- **Validation Success Rate**: Percentage of successful validations
- **Validation Duration**: Time to complete validation stages
- **Error Frequency**: Common validation failure patterns
- **Usage Patterns**: Pull request validation frequency

### Logging

- **Execution Mode**: Clear logging of validation vs deployment mode
- **Stage Decisions**: Log why stages are executed or skipped
- **Error Details**: Comprehensive error logging for troubleshooting
- **Performance**: Timing information for optimization

## Best Practices

### For Developers

1. **Run Local Validation**: Use local CDK commands before creating PR
2. **Small Changes**: Keep pull requests focused and small
3. **Check Status**: Monitor validation status after creating PR
4. **Fix Quickly**: Address validation failures promptly

### For Teams

1. **Validation First**: Don't review PRs with failing validation
2. **Fast Feedback**: Prioritize quick validation over comprehensive testing
3. **Error Patterns**: Track common validation failures for process improvement
4. **Documentation**: Keep validation documentation up to date

## Related Documentation

- **[Troubleshooting Guide](pr-validation-troubleshooting.md)** - Common issues and solutions
- **[Team Processes](../team-processes/pr-validation-process.md)** - Team workflow guidelines
- **[Infrastructure Deployment](infrastructure-deployment.md)** - Full deployment workflow
- **[Workflow Overview](README.md)** - Complete workflow documentation

---

**Last Updated**: July 25, 2025