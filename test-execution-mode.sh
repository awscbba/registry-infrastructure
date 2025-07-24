#!/bin/bash

# Test script to verify execution mode detection integration
set -e

echo "🧪 Testing Execution Mode Detection Integration"
echo "=============================================="

# Test function
test_execution_mode() {
    local trigger_type="$1"
    local branch_name="$2"
    local expected_mode="$3"
    local expected_skip_deployment="$4"
    local expected_skip_testing="$5"
    
    echo ""
    echo "🔍 Testing: $trigger_type trigger on $branch_name branch"
    echo "Expected: $expected_mode mode, skip_deployment=$expected_skip_deployment, skip_testing=$expected_skip_testing"
    
    # Set environment variables
    export CODECATALYST_TRIGGER_TYPE="$trigger_type"
    export CODECATALYST_SOURCE_BRANCH_NAME="$branch_name"
    
    # Run execution mode detection
    ./scripts/execution-mode-detection.sh > /dev/null
    
    # Source the results
    source execution-mode-env.sh
    
    # Verify results
    if [ "$EXECUTION_MODE" = "$expected_mode" ] && \
       [ "$SKIP_DEPLOYMENT" = "$expected_skip_deployment" ] && \
       [ "$SKIP_TESTING" = "$expected_skip_testing" ]; then
        echo "✅ PASS: Mode=$EXECUTION_MODE, Skip Deployment=$SKIP_DEPLOYMENT, Skip Testing=$SKIP_TESTING"
    else
        echo "❌ FAIL: Expected mode=$expected_mode, skip_deployment=$expected_skip_deployment, skip_testing=$expected_skip_testing"
        echo "         Got mode=$EXECUTION_MODE, skip_deployment=$SKIP_DEPLOYMENT, skip_testing=$SKIP_TESTING"
        return 1
    fi
}

# Test cases
echo "Running test cases..."

# Test 1: Pull request trigger (should always be validation mode)
test_execution_mode "PULLREQUEST" "main" "validation" "true" "true"
test_execution_mode "PULLREQUEST" "feature-branch" "validation" "true" "true"

# Test 2: Push to main (should be deployment mode)
test_execution_mode "PUSH" "main" "deployment" "false" "false"

# Test 3: Push to feature branch (should be validation mode)
test_execution_mode "PUSH" "feature-branch" "validation" "true" "true"

# Test 4: Manual trigger on main (should be deployment mode)
test_execution_mode "MANUAL" "main" "deployment" "false" "false"

# Test 5: Manual trigger on feature branch (should be validation mode)
test_execution_mode "MANUAL" "feature-branch" "validation" "true" "true"

# Test 6: Unknown trigger (should fallback to validation mode)
test_execution_mode "UNKNOWN" "main" "validation" "true" "true"

echo ""
echo "🎉 All tests passed! Execution mode detection is working correctly."

# Test workflow integration simulation
echo ""
echo "🔧 Testing workflow integration simulation..."

# Simulate CheckAPISync stage
echo "Simulating CheckAPISync stage..."
export CODECATALYST_TRIGGER_TYPE="PULLREQUEST"
export CODECATALYST_SOURCE_BRANCH_NAME="feature-test"
./scripts/execution-mode-detection.sh > /dev/null
source execution-mode-env.sh

if [ "$EXECUTION_MODE" = "validation" ]; then
    echo "✅ CheckAPISync: Execution mode correctly detected as validation"
else
    echo "❌ CheckAPISync: Expected validation mode, got $EXECUTION_MODE"
    exit 1
fi

# Simulate DeployInfrastructure stage decision
echo "Simulating DeployInfrastructure stage decision..."
if [ "$SKIP_DEPLOYMENT" = "true" ]; then
    echo "✅ DeployInfrastructure: Correctly skipping deployment for $EXECUTION_MODE mode"
    echo "   Would create placeholder artifacts..."
else
    echo "❌ DeployInfrastructure: Should skip deployment in validation mode"
    exit 1
fi

# Simulate PostDeploymentTests stage decision
echo "Simulating PostDeploymentTests stage decision..."
if [ "$SKIP_TESTING" = "true" ]; then
    echo "✅ PostDeploymentTests: Correctly skipping tests for $EXECUTION_MODE mode"
    echo "   Would create placeholder test report..."
else
    echo "❌ PostDeploymentTests: Should skip testing in validation mode"
    exit 1
fi

echo ""
echo "🎉 Workflow integration simulation passed!"
echo "✅ All execution mode detection functionality is working correctly!"