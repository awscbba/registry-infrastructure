# Execution Mode Detection Implementation

## Overview

This document describes the implementation of execution mode detection logic for the CodeCatalyst workflow, as specified in task 2 of the PR validation workflow specification.

## Implementation Details

### 1. Execution Mode Detection Script

**File**: `scripts/execution-mode-detection.sh`

This script implements comprehensive execution mode detection using the `CODECATALYST_TRIGGER_TYPE` environment variable and branch information to determine whether the workflow should run in validation or deployment mode.

#### Key Features:
- **Trigger Type Detection**: Uses `CODECATALYST_TRIGGER_TYPE` environment variable
- **Branch-based Logic**: Considers branch name for additional context
- **Fallback Mechanism**: Defaults to validation mode for unknown triggers
- **Comprehensive Logging**: Provides detailed logging for all decisions
- **Artifact Generation**: Creates execution context files for downstream stages

#### Execution Modes:

| Trigger Type | Branch | Execution Mode | Deploy | Test | Description |
|--------------|--------|----------------|--------|------|-------------|
| PULLREQUEST | Any | validation | ❌ | ❌ | Pull request validation only |
| PUSH | main | deployment | ✅ | ✅ | Full deployment pipeline |
| PUSH | feature | validation | ❌ | ❌ | Feature branch validation |
| MANUAL | main | deployment | ✅ | ✅ | Manual deployment |
| MANUAL | feature | validation | ❌ | ❌ | Manual validation |
| UNKNOWN | Any | validation | ❌ | ❌ | Fallback to validation |

### 2. Generated Artifacts

The script generates three key artifacts:

#### `execution-context.json`
```json
{
  "execution_mode": "validation|deployment",
  "trigger_type": "PULLREQUEST|PUSH|MANUAL|UNKNOWN",
  "branch_name": "string",
  "is_main_branch": boolean,
  "skip_deployment": boolean,
  "skip_testing": boolean,
  "timestamp": "ISO8601",
  "commit_ref": "string",
  "workflow_name": "string"
}
```

#### `execution-mode-env.sh`
Environment variables for use in subsequent workflow steps:
```bash
export EXECUTION_MODE="validation"
export TRIGGER_TYPE="PULLREQUEST"
export BRANCH_NAME="feature-branch"
export IS_MAIN_BRANCH="false"
export SKIP_DEPLOYMENT="true"
export SKIP_TESTING="true"
```

### 3. Workflow Integration

The execution mode detection has been integrated into all workflow actions:

#### CheckAPISync
- Executes execution mode detection script
- Sources environment variables
- Includes execution context in deployment context artifact
- Provides comprehensive logging

#### PrepareAPIIntegration
- Sources execution mode environment variables
- Logs execution context for transparency
- Maintains existing API integration logic

#### ValidateInfrastructure
- Sources execution mode environment variables
- Logs execution context
- Always runs regardless of mode (validation stage)

#### DeployInfrastructure
- Uses `SKIP_DEPLOYMENT` flag instead of branch-only logic
- Creates enhanced placeholder artifacts with execution mode context
- Includes execution mode information in deployment summary

#### PostDeploymentTests
- Uses `SKIP_TESTING` flag instead of branch-only logic
- Creates enhanced placeholder test reports with execution mode context
- Provides clear skip reasoning

#### NotifyDeploymentStatus
- Sources execution mode environment variables
- Creates mode-specific notifications (validation vs deployment)
- Includes execution context in all notifications
- Provides appropriate next steps based on mode

### 4. Logging Enhancements

All stages now include comprehensive execution mode logging:

```
📊 Execution Context:
  Mode: validation
  Trigger: PULLREQUEST
  Branch: feature-branch
  Skip Deployment: true
  Skip Testing: true
```

### 5. Testing

**File**: `test-execution-mode.sh`

Comprehensive test suite that validates:
- All trigger type and branch combinations
- Correct execution mode determination
- Proper environment variable export
- Workflow integration simulation

## Requirements Compliance

This implementation satisfies the following requirements from the specification:

### Requirement 3.2
✅ **"WHEN a workflow runs THEN it SHALL clearly log which trigger caused the execution"**
- All stages now log trigger type and execution context
- Comprehensive logging shows trigger type, branch, and mode decisions

### Requirement 3.3
✅ **"WHEN stages are skipped THEN the workflow SHALL log the reason for skipping with clear messaging"**
- Clear skip reasoning in all conditional stages
- Execution mode context provided in all skip messages
- Placeholder artifacts include skip reasons

## Usage

### In Workflow Actions

Each action now follows this pattern:

```bash
# Source execution mode environment variables
source execution-mode-env.sh

echo "📊 Execution Context:"
echo "  Mode: $EXECUTION_MODE"
echo "  Trigger: $TRIGGER_TYPE"
echo "  Branch: $BRANCH_NAME"
echo "  Skip Deployment: $SKIP_DEPLOYMENT"
echo "  Skip Testing: $SKIP_TESTING"

# Use flags for conditional logic
if [ "$SKIP_DEPLOYMENT" = "true" ]; then
    echo "ℹ️ Execution mode: $EXECUTION_MODE - skipping deployment"
    # Create placeholder artifacts
fi
```

### Testing Locally

```bash
# Test different scenarios
CODECATALYST_TRIGGER_TYPE=PULLREQUEST CODECATALYST_SOURCE_BRANCH_NAME=feature ./scripts/execution-mode-detection.sh
CODECATALYST_TRIGGER_TYPE=PUSH CODECATALYST_SOURCE_BRANCH_NAME=main ./scripts/execution-mode-detection.sh

# Run comprehensive tests
./test-execution-mode.sh
```

## Benefits

1. **Clear Execution Logic**: Explicit trigger-based mode determination
2. **Comprehensive Logging**: Full transparency of execution decisions
3. **Robust Fallbacks**: Safe defaults for unknown scenarios
4. **Testable**: Comprehensive test coverage for all scenarios
5. **Maintainable**: Centralized logic in reusable script
6. **Compliant**: Meets all specification requirements

## Future Enhancements

- Integration with external notification systems
- Metrics collection for execution mode usage
- Additional trigger types as CodeCatalyst evolves
- Enhanced error handling and recovery mechanisms