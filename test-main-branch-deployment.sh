#!/bin/bash

# Main Branch Deployment Workflow Test
# This script tests that the workflow correctly executes all stages for main branch deployments
# to ensure the conditional logic works properly in deployment mode

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/test-main-deployment"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

# Function to run a test and track results
run_test() {
    local test_name="$1"
    local test_function="$2"
    
    log_test "Running: $test_name"
    
    if $test_function; then
        log_success "✅ PASSED: $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "❌ FAILED: $test_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        FAILED_TESTS+=("$test_name")
        return 1
    fi
}

# Setup test environment
setup_test_environment() {
    log_info "Setting up test environment for main branch deployment..."
    
    # Create test directory
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"
    cd "$TEST_DIR"
    
    # Copy necessary files for testing
    cp -r "$SCRIPT_DIR/scripts" .
    cp -r "$SCRIPT_DIR/people_register_infrastructure" .
    cp -r "$SCRIPT_DIR/lambda" .
    
    # Make scripts executable
    chmod +x scripts/*.sh
    
    log_success "Test environment setup completed"
}

# Test 1: Execution mode detection for main branch push
test_main_branch_execution_mode() {
    log_info "Testing execution mode detection for main branch push..."
    
    # Simulate main branch push environment variables
    export CODECATALYST_TRIGGER_TYPE="PUSH"
    export CODECATALYST_SOURCE_BRANCH_NAME="main"
    export CODECATALYST_SOURCE_BRANCH_REF="def456abc789"
    export CODECATALYST_COMMIT_AUTHOR="developer@example.com"
    
    # Run execution mode detection
    if ./scripts/execution-mode-detection.sh > main-branch-test.log 2>&1; then
        # Verify execution mode is set to deployment
        source execution-mode-env.sh
        
        if [[ "$EXECUTION_MODE" == "deployment" ]] && \
           [[ "$TRIGGER_TYPE" == "PUSH" ]] && \
           [[ "$SKIP_DEPLOYMENT" == "false" ]] && \
           [[ "$SKIP_TESTING" == "false" ]] && \
           [[ "$IS_MAIN_BRANCH" == "true" ]]; then
            log_success "Execution mode correctly set to deployment for main branch push"
            return 0
        else
            log_error "Execution mode not correctly set. Expected: deployment, Got: $EXECUTION_MODE"
            log_error "Skip Deployment: $SKIP_DEPLOYMENT (expected: false)"
            log_error "Skip Testing: $SKIP_TESTING (expected: false)"
            return 1
        fi
    else
        log_error "Execution mode detection script failed"
        return 1
    fi
}

# Test 2: Manual trigger on main branch
test_manual_trigger_main_branch() {
    log_info "Testing manual trigger on main branch..."
    
    # Simulate manual trigger on main branch
    export CODECATALYST_TRIGGER_TYPE="MANUAL"
    export CODECATALYST_SOURCE_BRANCH_NAME="main"
    export CODECATALYST_ACTOR_NAME="admin@example.com"
    
    # Run execution mode detection
    if ./scripts/execution-mode-detection.sh > manual-trigger-test.log 2>&1; then
        source execution-mode-env.sh
        
        if [[ "$EXECUTION_MODE" == "deployment" ]] && \
           [[ "$TRIGGER_TYPE" == "MANUAL" ]] && \
           [[ "$SKIP_DEPLOYMENT" == "false" ]] && \
           [[ "$SKIP_TESTING" == "false" ]]; then
            log_success "Manual trigger on main branch correctly set to deployment mode"
            return 0
        else
            log_error "Manual trigger execution mode not correctly set"
            return 1
        fi
    else
        log_error "Manual trigger execution mode detection failed"
        return 1
    fi
}

# Test 3: Feature branch push (should still be validation)
test_feature_branch_push() {
    log_info "Testing feature branch push (should be validation mode)..."
    
    # Simulate feature branch push
    export CODECATALYST_TRIGGER_TYPE="PUSH"
    export CODECATALYST_SOURCE_BRANCH_NAME="feature/new-feature"
    export CODECATALYST_SOURCE_BRANCH_REF="ghi789jkl012"
    
    # Run execution mode detection
    if ./scripts/execution-mode-detection.sh > feature-branch-test.log 2>&1; then
        source execution-mode-env.sh
        
        if [[ "$EXECUTION_MODE" == "validation" ]] && \
           [[ "$TRIGGER_TYPE" == "PUSH" ]] && \
           [[ "$SKIP_DEPLOYMENT" == "true" ]] && \
           [[ "$SKIP_TESTING" == "true" ]] && \
           [[ "$IS_MAIN_BRANCH" == "false" ]]; then
            log_success "Feature branch push correctly set to validation mode"
            return 0
        else
            log_error "Feature branch push execution mode not correctly set"
            return 1
        fi
    else
        log_error "Feature branch push execution mode detection failed"
        return 1
    fi
}

# Test 4: Deployment mode stage execution plan
test_deployment_mode_stage_plan() {
    log_info "Testing deployment mode stage execution plan..."
    
    # Set up main branch deployment environment
    export CODECATALYST_TRIGGER_TYPE="PUSH"
    export CODECATALYST_SOURCE_BRANCH_NAME="main"
    
    # Run execution mode detection
    ./scripts/execution-mode-detection.sh > deployment-plan-test.log 2>&1
    source execution-mode-env.sh
    
    # Verify stage execution plan from log
    if grep -q "CheckAPISync - WILL EXECUTE (always runs)" deployment-plan-test.log && \
       grep -q "PrepareAPIIntegration - WILL EXECUTE (always runs)" deployment-plan-test.log && \
       grep -q "ValidateInfrastructure - WILL EXECUTE (always runs)" deployment-plan-test.log && \
       grep -q "DeployInfrastructure - WILL EXECUTE (deployment mode)" deployment-plan-test.log && \
       grep -q "PostDeploymentTests - WILL EXECUTE (deployment mode)" deployment-plan-test.log && \
       grep -q "NotifyDeploymentStatus - WILL EXECUTE" deployment-plan-test.log; then
        log_success "Deployment mode stage execution plan is correct"
        return 0
    else
        log_error "Deployment mode stage execution plan is incorrect"
        log_error "Log contents:"
        cat deployment-plan-test.log
        return 1
    fi
}

# Test 5: Deployment mode summary information
test_deployment_mode_summary() {
    log_info "Testing deployment mode summary information..."
    
    # Set up main branch deployment environment
    export CODECATALYST_TRIGGER_TYPE="PUSH"
    export CODECATALYST_SOURCE_BRANCH_NAME="main"
    
    # Run execution mode detection
    ./scripts/execution-mode-detection.sh > deployment-summary-test.log 2>&1
    
    # Verify deployment mode summary
    if grep -q "DEPLOYMENT MODE SUMMARY:" deployment-summary-test.log && \
       grep -q "Purpose: Deploy infrastructure changes to live environment" deployment-summary-test.log && \
       grep -q "Duration: ~15-30 minutes (full deployment cycle)" deployment-summary-test.log && \
       grep -q "Infrastructure: Live AWS resources created/updated" deployment-summary-test.log && \
       grep -q "Outcome: Live application deployment with post-deployment testing" deployment-summary-test.log; then
        log_success "Deployment mode summary information is correct"
        return 0
    else
        log_error "Deployment mode summary information is incorrect"
        return 1
    fi
}

# Test 6: Conditional logic consistency
test_conditional_logic_consistency() {
    log_info "Testing conditional logic consistency across different scenarios..."
    
    local scenarios=(
        "PUSH:main:deployment:false:false"
        "PUSH:feature/test:validation:true:true"
        "PULLREQUEST:feature/test:validation:true:true"
        "MANUAL:main:deployment:false:false"
        "MANUAL:feature/test:validation:true:true"
        "UNKNOWN:main:validation:true:true"
    )
    
    for scenario in "${scenarios[@]}"; do
        IFS=':' read -ra PARTS <<< "$scenario"
        local trigger="${PARTS[0]}"
        local branch="${PARTS[1]}"
        local expected_mode="${PARTS[2]}"
        local expected_skip_deploy="${PARTS[3]}"
        local expected_skip_test="${PARTS[4]}"
        
        log_info "Testing scenario: $trigger on $branch"
        
        # Set environment
        export CODECATALYST_TRIGGER_TYPE="$trigger"
        export CODECATALYST_SOURCE_BRANCH_NAME="$branch"
        
        # Run detection
        if ./scripts/execution-mode-detection.sh > "scenario-${trigger}-${branch//\//-}.log" 2>&1; then
            source execution-mode-env.sh
            
            if [[ "$EXECUTION_MODE" == "$expected_mode" ]] && \
               [[ "$SKIP_DEPLOYMENT" == "$expected_skip_deploy" ]] && \
               [[ "$SKIP_TESTING" == "$expected_skip_test" ]]; then
                log_success "✓ Scenario $trigger:$branch correctly configured"
            else
                log_error "✗ Scenario $trigger:$branch incorrectly configured"
                log_error "  Expected: mode=$expected_mode, skip_deploy=$expected_skip_deploy, skip_test=$expected_skip_test"
                log_error "  Got: mode=$EXECUTION_MODE, skip_deploy=$SKIP_DEPLOYMENT, skip_test=$SKIP_TESTING"
                return 1
            fi
        else
            log_error "✗ Scenario $trigger:$branch failed to execute"
            return 1
        fi
    done
    
    log_success "All conditional logic scenarios passed"
    return 0
}

# Generate test report
generate_test_report() {
    local total_tests=$((TESTS_PASSED + TESTS_FAILED))
    
    cat > "$TEST_DIR/main-branch-deployment-test-report.txt" << EOF
Main Branch Deployment Workflow Test Report
==========================================
Timestamp: $TIMESTAMP
Test Environment: $TEST_DIR

Test Summary:
============
Total Tests: $total_tests
Passed: $TESTS_PASSED
Failed: $TESTS_FAILED
Success Rate: $(( TESTS_PASSED * 100 / total_tests ))%

Test Results:
============
EOF
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo "✅ All tests passed!" >> "$TEST_DIR/main-branch-deployment-test-report.txt"
    else
        echo "❌ Failed tests:" >> "$TEST_DIR/main-branch-deployment-test-report.txt"
        for failed_test in "${FAILED_TESTS[@]}"; do
            echo "  - $failed_test" >> "$TEST_DIR/main-branch-deployment-test-report.txt"
        done
    fi
    
    cat >> "$TEST_DIR/main-branch-deployment-test-report.txt" << EOF

Test Coverage:
=============
✓ Main branch push execution mode detection (deployment mode)
✓ Manual trigger on main branch (deployment mode)
✓ Feature branch push (validation mode - for comparison)
✓ Deployment mode stage execution plan verification
✓ Deployment mode summary information verification
✓ Conditional logic consistency across all trigger/branch combinations

Conditional Logic Matrix Tested:
===============================
PUSH + main branch → deployment mode (all stages execute)
PUSH + feature branch → validation mode (deployment/testing skipped)
PULLREQUEST + any branch → validation mode (deployment/testing skipped)
MANUAL + main branch → deployment mode (all stages execute)
MANUAL + feature branch → validation mode (deployment/testing skipped)
UNKNOWN trigger + any branch → validation mode (safe fallback)

Test Environment Details:
========================
Final Configuration:
- Execution Mode: $EXECUTION_MODE
- Trigger Type: $TRIGGER_TYPE
- Branch Name: $BRANCH_NAME
- Skip Deployment: $SKIP_DEPLOYMENT
- Skip Testing: $SKIP_TESTING
- Is Main Branch: $IS_MAIN_BRANCH

Recommendations:
===============
EOF
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo "✅ Main branch deployment workflow logic is working correctly" >> "$TEST_DIR/main-branch-deployment-test-report.txt"
        echo "✅ Conditional execution logic properly handles all scenarios" >> "$TEST_DIR/main-branch-deployment-test-report.txt"
        echo "✅ Ready for production use" >> "$TEST_DIR/main-branch-deployment-test-report.txt"
    else
        echo "❌ Issues found in conditional logic that need to be addressed" >> "$TEST_DIR/main-branch-deployment-test-report.txt"
        echo "🔧 Review failed tests and fix conditional logic" >> "$TEST_DIR/main-branch-deployment-test-report.txt"
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."
    cd "$SCRIPT_DIR"
    log_info "Test artifacts preserved in: $TEST_DIR"
}

# Main test execution
main() {
    echo "🚀 Main Branch Deployment Workflow Test"
    echo "======================================="
    echo "Timestamp: $TIMESTAMP"
    echo "Test Directory: $TEST_DIR"
    echo ""
    
    # Setup
    setup_test_environment
    
    # Run all tests
    run_test "Main Branch Execution Mode Detection" test_main_branch_execution_mode
    run_test "Manual Trigger Main Branch" test_manual_trigger_main_branch
    run_test "Feature Branch Push (Validation)" test_feature_branch_push
    run_test "Deployment Mode Stage Plan" test_deployment_mode_stage_plan
    run_test "Deployment Mode Summary" test_deployment_mode_summary
    run_test "Conditional Logic Consistency" test_conditional_logic_consistency
    
    # Generate report
    generate_test_report
    
    # Display results
    echo ""
    echo "🏁 Test Execution Complete"
    echo "========================="
    echo "Total Tests: $((TESTS_PASSED + TESTS_FAILED))"
    echo "Passed: $TESTS_PASSED"
    echo "Failed: $TESTS_FAILED"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        log_success "🎉 All tests passed! Main branch deployment workflow logic is working correctly."
        echo ""
        echo "📋 Test Report: $TEST_DIR/main-branch-deployment-test-report.txt"
        echo "📁 Test Artifacts: $TEST_DIR/"
        
        cleanup
        exit 0
    else
        log_error "❌ Some tests failed. Review the test report for details."
        echo ""
        echo "📋 Test Report: $TEST_DIR/main-branch-deployment-test-report.txt"
        echo "📁 Test Artifacts: $TEST_DIR/"
        echo ""
        echo "Failed Tests:"
        for failed_test in "${FAILED_TESTS[@]}"; do
            echo "  - $failed_test"
        done
        
        cleanup
        exit 1
    fi
}

# Run main function
main "$@"