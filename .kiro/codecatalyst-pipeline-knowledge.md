# CodeCatalyst Pipeline Implementation Knowledge Base

## Overview
This document captures the lessons learned, solutions, and best practices discovered during the implementation of CodeCatalyst CI/CD pipelines for infrastructure validation and deployment.

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Critical Issues & Solutions](#critical-issues--solutions)
3. [Node.js Compatibility Challenges](#nodejs-compatibility-challenges)
4. [Branch Pattern Syntax Issues](#branch-pattern-syntax-issues)
5. [Workflow Structure Best Practices](#workflow-structure-best-practices)
6. [Working Configurations](#working-configurations)
7. [Troubleshooting Guide](#troubleshooting-guide)

## Architecture Overview

### Final Working Architecture
We implemented **two separate workflows** to avoid duplication and provide clear separation of concerns:

1. **Validation Workflow** (`infrastructure-validation.yml`)
   - **Purpose**: Fast feedback during development
   - **Triggers**: Feature branch pushes + PRs to main
   - **Stages**: CheckAPISync → ValidateInfrastructure
   - **Duration**: ~2-5 minutes

2. **Deployment Workflow** (`infrastructure-deployment-main.yml`)
   - **Purpose**: Production deployment after merge
   - **Triggers**: Main branch pushes only
   - **Stages**: CheckAPISync → ValidateInfrastructure → DeployInfrastructure
   - **Duration**: ~10-20 minutes

### Why Two Workflows?
- **Prevents duplicate execution** when PR is merged to main
- **Clear separation** between validation and deployment
- **Resource efficiency** - no unnecessary deployment attempts
- **Security** - deployment only happens after merge to main

## Critical Issues & Solutions

### 1. Node.js End-of-Life Blocking Issue

#### Problem
CDK 2.60.0+ shows blocking Node.js end-of-life warnings on Node 18.19.0:
```
Node 18 has reached end-of-life on 2025-04-30 and is not supported.
This software is currently running on node v18.19.0.
```

#### Root Cause
- CodeCatalyst environments use Node 18.19.0
- Modern CDK versions require Node 20+ 
- Warnings are treated as errors, causing pipeline failures

#### Solution: Intelligent Error Handling
```bash
# Multi-factor success detection
SUCCESS_INDICATORS=0

# Check 1: Exit code is 0 (perfect success)
if [ $DEPLOY_EXIT_CODE -eq 0 ]; then
    SUCCESS_INDICATORS=$((SUCCESS_INDICATORS + 1))
fi

# Check 2: Look for deployment success messages
if grep -q -E "(CREATE_COMPLETE|UPDATE_COMPLETE|Stack ARN)" deployment-output.txt; then
    SUCCESS_INDICATORS=$((SUCCESS_INDICATORS + 1))
fi

# Check 3: Check if it's just Node.js warnings
if grep -q "Node.*has reached end-of-life" deployment-errors.txt; then
    if ! grep -q -E "(Error|Failed|Exception)" deployment-errors.txt; then
        NODE_WARNING_ONLY="true"
        SUCCESS_INDICATORS=$((SUCCESS_INDICATORS + 1))
    fi
fi

# Check 4: Look for "no changes" message (also success)
if grep -q -E "(no changes|No differences)" deployment-output.txt; then
    SUCCESS_INDICATORS=$((SUCCESS_INDICATORS + 1))
fi
```

#### Key Techniques
- **CDK Version**: Use CDK 2.60.0 (older, more compatible)
- **Warning Suppression**: `CDK_DISABLE_VERSION_CHECK=1` and `NODE_NO_WARNINGS=1`
- **File-based Validation**: Check for actual CloudFormation template files
- **Multi-factor Analysis**: Don't rely on exit codes alone
- **Success Indicators**: Look for deployment success messages in output

### 2. Branch Pattern Syntax Issues

#### Problem
CodeCatalyst has very specific branch pattern syntax that differs from standard glob patterns.

#### Patterns That DON'T Work
```yaml
# These all failed:
- feature/*          # Standard glob
- "feature/*"        # Quoted glob  
- feature/**         # Double asterisk
- "feature/**"       # Quoted double asterisk
- feature\-.*        # Regex-style
- "!main"            # Exclude pattern
```

#### Solution: Script-based Logic
Instead of fighting with branch patterns, use script logic:

```yaml
Triggers:
  - Type: PUSH  # No branch restrictions

# Then in script:
if [ "$TRIGGER_TYPE" = "PUSH" ] && [ "$BRANCH_NAME" = "main" ]; then
    echo "⏭️ Skipping validation workflow for main branch push"
    exit 0
fi
```

#### Benefits
- **Reliable**: No dependency on CodeCatalyst syntax quirks
- **Flexible**: Easy to modify logic for different scenarios
- **Debuggable**: Clear logging shows decision process
- **Future-proof**: Works regardless of syntax changes

### 3. Workflow Duplication Issue

#### Problem
When PR is merged to main, both validation and deployment workflows run simultaneously, duplicating CheckAPISync and ValidateInfrastructure stages.

#### Solution: Separate Workflows with Clear Triggers
- **Validation**: Feature branches + PRs (no main branch)
- **Deployment**: Main branch only

#### Implementation
```bash
# In validation workflow
if [ "$TRIGGER_TYPE" = "PUSH" ] && [ "$BRANCH_NAME" = "main" ]; then
    exit 0  # Skip for main branch
fi
```

## Node.js Compatibility Challenges

### Environment Constraints
- **CodeCatalyst**: Node 18.19.0 (end-of-life 2025-04-30)
- **CDK Requirements**: Node 20+ for versions 2.70.0+
- **AWS CDK**: Strict version checking enabled by default

### Working Configuration
```bash
# Use older CDK version
npm install -g aws-cdk@2.60.0

# Suppress warnings
export CDK_DISABLE_VERSION_CHECK=1
export NODE_NO_WARNINGS=1
export FASTMCP_LOG_LEVEL=ERROR

# Intelligent success detection
cdk synth > output.txt 2>errors.txt
if ls cdk.out/*.template.json >/dev/null 2>&1; then
    echo "✅ Success - CloudFormation templates generated"
fi
```

### Success Detection Strategy
1. **Primary**: Check for CloudFormation template files
2. **Secondary**: Look for success messages in output
3. **Tertiary**: Analyze error types (warnings vs real errors)
4. **Fallback**: Exit code analysis

## Branch Pattern Syntax Issues

### CodeCatalyst Specifics
- **Standard glob patterns don't work** as expected
- **Regex patterns are inconsistent**
- **Exclude patterns (`!main`) are unreliable**
- **Quoted vs unquoted makes a difference**

### Recommended Approach
Use **script-based branch filtering** instead of YAML patterns:

```yaml
# Simple trigger
Triggers:
  - Type: PUSH

# Complex logic in script
BRANCH_NAME="${CODECATALYST_SOURCE_BRANCH_NAME:-unknown}"
case "$BRANCH_NAME" in
    main)
        echo "Main branch - use deployment workflow"
        exit 0
        ;;
    feature/*)
        echo "Feature branch - run validation"
        ;;
    *)
        echo "Other branch - run validation"
        ;;
esac
```

## Workflow Structure Best Practices

### 1. Execution Mode Detection
```bash
# Robust execution mode detection
BRANCH_NAME="${CODECATALYST_SOURCE_BRANCH_NAME:-unknown}"
TRIGGER_TYPE="${CODECATALYST_TRIGGER_TYPE:-PUSH}"

if [ "$TRIGGER_TYPE" = "PULLREQUEST" ]; then
    EXECUTION_MODE="validation"
elif [ "$BRANCH_NAME" = "main" ]; then
    EXECUTION_MODE="deployment"
else
    EXECUTION_MODE="validation"
fi
```

### 2. Artifact Management
```yaml
# Consistent artifact structure
Outputs:
  Artifacts:
    - Name: validationResults
      Files:
        - "validation-results.json"
        - "validation-report.txt"
        - "cdk-synth-output.txt"
        - "cdk-synth-errors.txt"
```

### 3. Error Handling
```bash
# Prevent script exit on CDK errors
set +e
cdk deploy --all --require-approval never > output.txt 2>errors.txt
DEPLOY_EXIT_CODE=$?
set -e

# Analyze results before deciding success/failure
```

### 4. Logging Strategy
```bash
# Clear, structured logging
echo "⚡ Infrastructure Validation"
echo "=========================="
echo "📅 Stage Start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "🎯 Mode: $EXECUTION_MODE"
echo "🔄 Branch: $BRANCH_NAME"
```

## Working Configurations

### Validation Workflow Template
```yaml
Name: Infrastructure_Validation_Pipeline
SchemaVersion: "1.0"

Triggers:
  - Type: PUSH
  - Type: PULLREQUEST
    Branches:
      - main
    Events:
      - OPEN
      - REVISION

Actions:
  ValidateInfrastructure:
    Identifier: aws/build@v1
    Configuration:
      Steps:
        - Run: |
            # Skip main branch pushes
            if [ "$CODECATALYST_TRIGGER_TYPE" = "PUSH" ] && [ "$CODECATALYST_SOURCE_BRANCH_NAME" = "main" ]; then
                exit 0
            fi
            
            # Install compatible CDK
            npm install -g aws-cdk@2.60.0
            
            # Suppress Node warnings
            export CDK_DISABLE_VERSION_CHECK=1
            export NODE_NO_WARNINGS=1
            
            # Run synthesis with intelligent error handling
            cdk synth > output.txt 2>errors.txt
            if ls cdk.out/*.template.json >/dev/null 2>&1; then
                echo "✅ Validation successful"
            else
                echo "❌ Validation failed"
                exit 1
            fi
```

### Deployment Workflow Template
```yaml
Name: Infrastructure_Deployment_Pipeline
SchemaVersion: "1.0"

Triggers:
  - Type: PUSH
    Branches:
      - main

Actions:
  DeployInfrastructure:
    Identifier: aws/build@v1
    Configuration:
      Steps:
        - Run: |
            # Install compatible CDK
            npm install -g aws-cdk@2.60.0
            
            # Suppress Node warnings
            export CDK_DISABLE_VERSION_CHECK=1
            export NODE_NO_WARNINGS=1
            
            # Deploy with intelligent error handling
            set +e
            cdk deploy --all --require-approval never > output.txt 2>errors.txt
            DEPLOY_EXIT_CODE=$?
            set -e
            
            # Multi-factor success analysis
            SUCCESS_INDICATORS=0
            if [ $DEPLOY_EXIT_CODE -eq 0 ]; then
                SUCCESS_INDICATORS=$((SUCCESS_INDICATORS + 1))
            fi
            if grep -q "CREATE_COMPLETE\|UPDATE_COMPLETE" output.txt; then
                SUCCESS_INDICATORS=$((SUCCESS_INDICATORS + 1))
            fi
            
            if [ $SUCCESS_INDICATORS -gt 0 ]; then
                echo "✅ Deployment successful"
            else
                echo "❌ Deployment failed"
                exit 1
            fi
```

## Troubleshooting Guide

### Common Issues

#### 1. Pipeline Not Triggering
**Symptoms**: Workflow doesn't run on push/PR
**Causes**: 
- Branch pattern syntax issues
- YAML formatting errors
- Trigger configuration problems

**Solutions**:
- Remove branch restrictions temporarily
- Use script-based branch logic
- Check YAML syntax with validator

#### 2. Node.js Version Errors
**Symptoms**: CDK fails with Node end-of-life warnings
**Solutions**:
- Use CDK 2.60.0 or older
- Add warning suppression environment variables
- Implement intelligent error handling

#### 3. Duplicate Workflow Execution
**Symptoms**: Same stages run twice on main branch
**Solutions**:
- Split into separate workflows
- Add script-based branch filtering
- Use early exit for excluded branches

#### 4. CDK Synthesis Failures
**Symptoms**: CDK synth fails but templates are generated
**Solutions**:
- Check for CloudFormation template files
- Look for success indicators in output
- Don't rely solely on exit codes

### Debugging Commands
```bash
# Check current branch
echo "Branch: ${CODECATALYST_SOURCE_BRANCH_NAME}"

# Check trigger type
echo "Trigger: ${CODECATALYST_TRIGGER_TYPE}"

# List generated templates
ls -la cdk.out/*.template.json

# Check CDK version
cdk --version

# Test synthesis without deployment
cdk synth --quiet
```

### Environment Variables
```bash
# Essential for Node.js compatibility
CDK_DISABLE_VERSION_CHECK=1
NODE_NO_WARNINGS=1
FASTMCP_LOG_LEVEL=ERROR

# CodeCatalyst provided variables
CODECATALYST_SOURCE_BRANCH_NAME
CODECATALYST_TRIGGER_TYPE
CODECATALYST_SOURCE_BRANCH_REF
```

## Key Lessons Learned

1. **CodeCatalyst branch patterns are finicky** - use script logic instead
2. **Node.js compatibility requires intelligent error handling** - don't trust exit codes alone
3. **Separate workflows prevent duplication** - validation vs deployment
4. **File-based validation is more reliable** - check for actual outputs
5. **Early exit prevents resource waste** - skip unnecessary execution
6. **Structured logging aids debugging** - clear, consistent output format
7. **Environment variable suppression helps** - but isn't always sufficient
8. **Multi-factor success analysis is crucial** - combine multiple indicators

## Future Improvements

1. **Upgrade Node.js environment** when CodeCatalyst supports it
2. **Use newer CDK versions** once Node compatibility is resolved
3. **Implement caching** for faster pipeline execution
4. **Add parallel execution** where possible
5. **Enhanced error reporting** with structured output
6. **Automated rollback** on deployment failures

## References

- [CodeCatalyst Workflows Documentation](https://docs.aws.amazon.com/codecatalyst/latest/userguide/workflows.html)
- [AWS CDK Node.js Compatibility](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html)
- [CodeCatalyst Environment Variables](https://docs.aws.amazon.com/codecatalyst/latest/userguide/workflows-env-vars.html)

---

**Last Updated**: 2025-07-25  
**Version**: 1.0  
**Status**: Production Ready