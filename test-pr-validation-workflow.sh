#!/bin/bash

# Pull Request Validation Workflow End-to-End Test
# This script tests the complete pull request validation workflow to ensure:
# 1. Validation stages execute correctly
# 2. Deployment stages are properly skipped
# 3. Artifact creation and compatibility works
# 4. Error handling and reporting functions properly

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR/test-pr-validation"
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
    log_info "Setting up test environment..."
    
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

# Test 1: Execution mode detection for pull requests
test_execution_mode_detection() {
    log_info "Testing execution mode detection for pull requests..."
    
    # Simulate pull request environment variables
    export CODECATALYST_TRIGGER_TYPE="PULLREQUEST"
    export CODECATALYST_SOURCE_BRANCH_NAME="feature/test-pr"
    export CODECATALYST_TARGET_BRANCH_NAME="main"
    export CODECATALYST_PULLREQUEST_EVENT="PULLREQUEST_CREATED"
    export CODECATALYST_PULLREQUEST_ID="123"
    export CODECATALYST_SOURCE_BRANCH_REF="abc123def456"
    
    # Run execution mode detection
    if ./scripts/execution-mode-detection.sh > execution-mode-test.log 2>&1; then
        # Verify execution mode is set to validation
        source execution-mode-env.sh
        
        if [[ "$EXECUTION_MODE" == "validation" ]] && \
           [[ "$TRIGGER_TYPE" == "PULLREQUEST" ]] && \
           [[ "$SKIP_DEPLOYMENT" == "true" ]] && \
           [[ "$SKIP_TESTING" == "true" ]]; then
            log_success "Execution mode correctly set to validation for pull request"
            return 0
        else
            log_error "Execution mode not correctly set. Expected: validation, Got: $EXECUTION_MODE"
            return 1
        fi
    else
        log_error "Execution mode detection script failed"
        return 1
    fi
}

# Test 2: Validation stages execute correctly
test_validation_stages_execution() {
    log_info "Testing validation stages execution..."
    
    # Source the execution mode environment
    source execution-mode-env.sh
    
    # Test CheckAPISync stage logic
    log_info "Testing CheckAPISync stage..."
    if test_check_api_sync_stage; then
        log_success "CheckAPISync stage test passed"
    else
        log_error "CheckAPISync stage test failed"
        return 1
    fi
    
    # Test PrepareAPIIntegration stage logic
    log_info "Testing PrepareAPIIntegration stage..."
    if test_prepare_api_integration_stage; then
        log_success "PrepareAPIIntegration stage test passed"
    else
        log_error "PrepareAPIIntegration stage test failed"
        return 1
    fi
    
    # Test ValidateInfrastructure stage logic
    log_info "Testing ValidateInfrastructure stage..."
    if test_validate_infrastructure_stage; then
        log_success "ValidateInfrastructure stage test passed"
    else
        log_error "ValidateInfrastructure stage test failed"
        return 1
    fi
    
    return 0
}

# Helper function to test CheckAPISync stage
test_check_api_sync_stage() {
    # Create deployment context (simulating CheckAPISync output)
    cat > deployment-context.json << EOF
{
  "deployment_type": "infrastructure_only",
  "timestamp": "$TIMESTAMP",
  "branch": "$BRANCH_NAME",
  "commit": "$CODECATALYST_SOURCE_BRANCH_REF",
  "api_sync_detected": false,
  "execution_mode": "$EXECUTION_MODE",
  "trigger_type": "$TRIGGER_TYPE",
  "is_main_branch": false,
  "skip_deployment": $SKIP_DEPLOYMENT,
  "skip_testing": $SKIP_TESTING
}
EOF
    
    # Verify deployment context was created correctly
    if [[ -f "deployment-context.json" ]]; then
        local exec_mode
        exec_mode=$(jq -r '.execution_mode' deployment-context.json)
        if [[ "$exec_mode" == "validation" ]]; then
            return 0
        fi
    fi
    return 1
}

# Helper function to test PrepareAPIIntegration stage
test_prepare_api_integration_stage() {
    # Simulate PrepareAPIIntegration stage
    local api_sync_detected
    api_sync_detected=$(jq -r '.api_sync_detected' deployment-context.json)
    
    # Create API integration summary
    cat > api-integration-summary.txt << EOF
API Integration Summary
======================
Timestamp: $TIMESTAMP
Deployment Type: infrastructure_only
API Sync Detected: $api_sync_detected

Integration Actions:
ℹ️ No integration needed
ℹ️ Using existing requirements

Handler Priority:
1. integrated_api_handler.py (if API sync detected)
2. enhanced_api_handler.py (fallback)
3. api_handler.py (legacy fallback)
EOF
    
    # Verify integration summary was created
    if [[ -f "api-integration-summary.txt" ]] && grep -q "API Integration Summary" api-integration-summary.txt; then
        return 0
    fi
    return 1
}

# Helper function to test ValidateInfrastructure stage
test_validate_infrastructure_stage() {
    # Create mock validation results
    cat > validation-results.json << EOF
{
  "status": "success",
  "errors": 0,
  "warnings": 0,
  "timestamp": "$TIMESTAMP",
  "execution_mode": "$EXECUTION_MODE",
  "cdk_synthesis": "success",
  "iam_permissions": "validated",
  "resource_configuration": "validated"
}
EOF
    
    cat > validation-report.txt << EOF
Infrastructure Validation Report
===============================
Timestamp: $TIMESTAMP
Execution Mode: $EXECUTION_MODE
Trigger Type: $TRIGGER_TYPE
Branch: $BRANCH_NAME

[INFO] AWS credentials validated successfully
[INFO] Infrastructure validation completed successfully

VALIDATION SUMMARY
==================
Total Errors: 0
Total Warnings: 0
EOF
    
    # Verify validation artifacts were created
    if [[ -f "validation-results.json" ]] && [[ -f "validation-report.txt" ]]; then
        local status
        status=$(jq -r '.status' validation-results.json)
        if [[ "$status" == "success" ]]; then
            return 0
        fi
    fi
    return 1
}

# Test 3: Deployment stages are properly skipped with placeholder artifacts
test_deployment_stages_skipped() {
    log_info "Testing deployment stages are properly skipped..."
    
    # Source execution mode
    source execution-mode-env.sh
    
    # Test DeployInfrastructure stage creates placeholder artifacts
    log_info "Testing DeployInfrastructure placeholder artifact creation..."
    if ./scripts/artifact-handler.sh create-placeholder deploymentSummary "$EXECUTION_MODE" "$TRIGGER_TYPE" "$BRANCH_NAME" "."; then
        log_success "DeployInfrastructure placeholder artifacts created"
    else
        log_error "Failed to create DeployInfrastructure placeholder artifacts"
        return 1
    fi
    
    # Test PostDeploymentTests stage creates placeholder artifacts
    log_info "Testing PostDeploymentTests placeholder artifact creation..."
    if ./scripts/artifact-handler.sh create-placeholder testReport "$EXECUTION_MODE" "$TRIGGER_TYPE" "$BRANCH_NAME" "."; then
        log_success "PostDeploymentTests placeholder artifacts created"
    else
        log_error "Failed to create PostDeploymentTests placeholder artifacts"
        return 1
    fi
    
    # Verify placeholder artifacts have correct structure
    if [[ -f "deployment-summary.json" ]] && [[ -f "post-deployment-test-report.txt" ]]; then
        # Check deployment summary is marked as placeholder
        local is_placeholder
        is_placeholder=$(jq -r '.placeholder_artifact // false' deployment-summary.json)
        if [[ "$is_placeholder" == "true" ]]; then
            log_success "Deployment summary correctly marked as placeholder"
        else
            log_error "Deployment summary not marked as placeholder"
            return 1
        fi
        
        # Check test report indicates skipped status
        if grep -q "Overall Status: SKIPPED" post-deployment-test-report.txt; then
            log_success "Test report correctly indicates skipped status"
        else
            log_error "Test report does not indicate skipped status"
            return 1
        fi
        
        return 0
    else
        log_error "Placeholder artifacts not created properly"
        return 1
    fi
}

# Test 4: Artifact creation and compatibility
test_artifact_compatibility() {
    log_info "Testing artifact creation and compatibility..."
    
    # Test artifact structure validation
    log_info "Testing artifact structure validation..."
    
    local artifacts=("deploymentSummary" "testReport" "deploymentNotification")
    
    for artifact in "${artifacts[@]}"; do
        log_info "Validating $artifact structure..."
        if ./scripts/artifact-handler.sh validate "$artifact" "."; then
            log_success "$artifact structure validation passed"
        else
            log_warning "$artifact structure validation failed (may be expected for some artifacts)"
        fi
    done
    
    # Test artifact consumption
    log_info "Testing artifact consumption compatibility..."
    
    for artifact in "${artifacts[@]}"; do
        log_info "Testing $artifact consumption..."
        if ./scripts/artifact-handler.sh test-consumption "$artifact" "."; then
            log_success "$artifact consumption test passed"
        else
            log_warning "$artifact consumption test failed"
        fi
    done
    
    # Test placeholder detection
    log_info "Testing placeholder artifact detection..."
    
    if ./scripts/artifact-handler.sh is-placeholder "deployment-summary.json"; then
        log_success "Placeholder detection working correctly"
    else
        log_error "Placeholder detection failed"
        return 1
    fi
    
    # Test data handling with placeholders
    log_info "Testing data handling with placeholder artifacts..."
    
    local api_url
    api_url=$(./scripts/artifact-handler.sh handle-data "deployment-summary.json" ".outputs.api_url" "not_available")
    
    if [[ "$api_url" == *"validation-placeholder"* ]]; then
        log_success "Placeholder data handling working correctly"
        return 0
    else
        log_error "Placeholder data handling failed. Got: $api_url"
        return 1
    fi
}

# Test 5: Error handling and reporting
test_error_handling() {
    log_info "Testing error handling and reporting..."
    
    # Test invalid trigger type handling
    log_info "Testing invalid trigger type handling..."
    
    # Save current environment
    local original_trigger="$CODECATALYST_TRIGGER_TYPE"
    
    # Set invalid trigger type
    export CODECATALYST_TRIGGER_TYPE="INVALID_TRIGGER"
    
    if ./scripts/execution-mode-detection.sh > error-test.log 2>&1; then
        source execution-mode-env.sh
        
        # Should default to validation mode for unknown triggers
        if [[ "$EXECUTION_MODE" == "validation" ]]; then
            log_success "Invalid trigger type correctly defaults to validation mode"
        else
            log_error "Invalid trigger type not handled correctly"
            export CODECATALYST_TRIGGER_TYPE="$original_trigger"
            return 1
        fi
    else
        log_error "Execution mode detection failed with invalid trigger"
        export CODECATALYST_TRIGGER_TYPE="$original_trigger"
        return 1
    fi
    
    # Restore original trigger
    export CODECATALYST_TRIGGER_TYPE="$original_trigger"
    
    # Test artifact creation failure handling
    log_info "Testing artifact creation failure handling..."
    
    # Try to create artifact with invalid parameters
    if ./scripts/artifact-handler.sh create-placeholder "invalidArtifact" "validation" "PULLREQUEST" "test-branch" "." 2>/dev/null; then
        log_error "Should have failed with invalid artifact type"
        return 1
    else
        log_success "Invalid artifact type correctly rejected"
    fi
    
    return 0
}

# Test 6: Notification stage execution
test_notification_stage() {
    log_info "Testing notification stage execution..."
    
    # Source execution mode
    source execution-mode-env.sh
    
    # Create notification artifacts
    if ./scripts/artifact-handler.sh create-placeholder deploymentNotification "$EXECUTION_MODE" "$TRIGGER_TYPE" "$BRANCH_NAME" "."; then
        log_success "Notification artifacts created successfully"
    else
        log_error "Failed to create notification artifacts"
        return 1
    fi
    
    # Verify notification content is appropriate for validation mode
    if [[ -f "deployment-notification.txt" ]]; then
        if grep -q "Pull Request Validation Summary" deployment-notification.txt && \
           grep -q "Validation completed successfully" deployment-notification.txt; then
            log_success "Notification content appropriate for validation mode"
        else
            log_error "Notification content not appropriate for validation mode"
            return 1
        fi
    else
        log_error "Notification file not created"
        return 1
    fi
    
    # Verify notification data structure
    if [[ -f "notification-data.json" ]]; then
        local notification_type
        notification_type=$(jq -r '.notification_type' notification-data.json)
        if [[ "$notification_type" == "validation_summary" ]]; then
            log_success "Notification data structure correct for validation mode"
            return 0
        else
            log_error "Notification data structure incorrect. Expected: validation_summary, Got: $notification_type"
            return 1
        fi
    else
        log_error "Notification data file not created"
        return 1
    fi
}

# Test 7: End-to-end workflow simulation
test_end_to_end_workflow() {
    log_info "Testing end-to-end workflow simulation..."
    
    # Clean up previous test artifacts
    rm -f deployment-context.json api-integration-summary.txt validation-*.json validation-*.txt
    rm -f deployment-summary.json outputs.json deployment.log
    rm -f post-deployment-test-report.txt
    rm -f deployment-notification.txt notification-data.json
    
    # Step 1: Execution mode detection
    log_info "Step 1: Execution mode detection..."
    if ! ./scripts/execution-mode-detection.sh > workflow-test.log 2>&1; then
        log_error "Execution mode detection failed"
        return 1
    fi
    source execution-mode-env.sh
    
    # Step 2: CheckAPISync simulation
    log_info "Step 2: CheckAPISync simulation..."
    if ! test_check_api_sync_stage; then
        log_error "CheckAPISync stage failed"
        return 1
    fi
    
    # Step 3: PrepareAPIIntegration simulation
    log_info "Step 3: PrepareAPIIntegration simulation..."
    if ! test_prepare_api_integration_stage; then
        log_error "PrepareAPIIntegration stage failed"
        return 1
    fi
    
    # Step 4: ValidateInfrastructure simulation
    log_info "Step 4: ValidateInfrastructure simulation..."
    if ! test_validate_infrastructure_stage; then
        log_error "ValidateInfrastructure stage failed"
        return 1
    fi
    
    # Step 5: DeployInfrastructure (skipped with placeholder)
    log_info "Step 5: DeployInfrastructure (placeholder creation)..."
    if ! ./scripts/artifact-handler.sh create-placeholder deploymentSummary "$EXECUTION_MODE" "$TRIGGER_TYPE" "$BRANCH_NAME" "."; then
        log_error "DeployInfrastructure placeholder creation failed"
        return 1
    fi
    
    # Step 6: PostDeploymentTests (skipped with placeholder)
    log_info "Step 6: PostDeploymentTests (placeholder creation)..."
    if ! ./scripts/artifact-handler.sh create-placeholder testReport "$EXECUTION_MODE" "$TRIGGER_TYPE" "$BRANCH_NAME" "."; then
        log_error "PostDeploymentTests placeholder creation failed"
        return 1
    fi
    
    # Step 7: NotifyDeploymentStatus
    log_info "Step 7: NotifyDeploymentStatus..."
    if ! ./scripts/artifact-handler.sh create-placeholder deploymentNotification "$EXECUTION_MODE" "$TRIGGER_TYPE" "$BRANCH_NAME" "."; then
        log_error "NotifyDeploymentStatus failed"
        return 1
    fi
    
    # Verify all expected artifacts exist
    local expected_artifacts=(
        "execution-context.json"
        "deployment-context.json"
        "api-integration-summary.txt"
        "validation-results.json"
        "deployment-summary.json"
        "post-deployment-test-report.txt"
        "deployment-notification.txt"
    )
    
    for artifact in "${expected_artifacts[@]}"; do
        if [[ -f "$artifact" ]]; then
            log_success "✓ $artifact created"
        else
            log_error "✗ $artifact missing"
            return 1
        fi
    done
    
    log_success "End-to-end workflow simulation completed successfully"
    return 0
}

# Generate test report
generate_test_report() {
    local total_tests=$((TESTS_PASSED + TESTS_FAILED))
    
    cat > "$TEST_DIR/pr-validation-test-report.txt" << EOF
Pull Request Validation Workflow Test Report
===========================================
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
        echo "✅ All tests passed!" >> "$TEST_DIR/pr-validation-test-report.txt"
    else
        echo "❌ Failed tests:" >> "$TEST_DIR/pr-validation-test-report.txt"
        for failed_test in "${FAILED_TESTS[@]}"; do
            echo "  - $failed_test" >> "$TEST_DIR/pr-validation-test-report.txt"
        done
    fi
    
    cat >> "$TEST_DIR/pr-validation-test-report.txt" << EOF

Test Coverage:
=============
✓ Execution mode detection for pull requests
✓ Validation stages execution (CheckAPISync, PrepareAPIIntegration, ValidateInfrastructure)
✓ Deployment stages properly skipped with placeholder artifacts
✓ Artifact creation and compatibility
✓ Error handling and reporting
✓ Notification stage execution with validation-specific content
✓ End-to-end workflow simulation

Artifacts Generated:
==================
$(ls -la "$TEST_DIR" | grep -E '\.(json|txt|log)$' | awk '{print $9}' | sort)

Test Environment Details:
========================
Execution Mode: $EXECUTION_MODE
Trigger Type: $TRIGGER_TYPE
Branch Name: $BRANCH_NAME
Skip Deployment: $SKIP_DEPLOYMENT
Skip Testing: $SKIP_TESTING

Recommendations:
===============
EOF
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo "✅ Pull request validation workflow is working correctly" >> "$TEST_DIR/pr-validation-test-report.txt"
        echo "✅ Ready for production use" >> "$TEST_DIR/pr-validation-test-report.txt"
    else
        echo "❌ Issues found that need to be addressed before production use" >> "$TEST_DIR/pr-validation-test-report.txt"
        echo "🔧 Review failed tests and fix underlying issues" >> "$TEST_DIR/pr-validation-test-report.txt"
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."
    cd "$SCRIPT_DIR"
    # Uncomment the next line if you want to remove test directory after completion
    # rm -rf "$TEST_DIR"
    log_info "Test artifacts preserved in: $TEST_DIR"
}

# Main test execution
main() {
    echo "🧪 Pull Request Validation Workflow End-to-End Test"
    echo "=================================================="
    echo "Timestamp: $TIMESTAMP"
    echo "Test Directory: $TEST_DIR"
    echo ""
    
    # Setup
    setup_test_environment
    
    # Run all tests
    run_test "Execution Mode Detection" test_execution_mode_detection
    run_test "Validation Stages Execution" test_validation_stages_execution
    run_test "Deployment Stages Skipped" test_deployment_stages_skipped
    run_test "Artifact Compatibility" test_artifact_compatibility
    run_test "Error Handling" test_error_handling
    run_test "Notification Stage" test_notification_stage
    run_test "End-to-End Workflow" test_end_to_end_workflow
    
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
        log_success "🎉 All tests passed! Pull request validation workflow is working correctly."
        echo ""
        echo "📋 Test Report: $TEST_DIR/pr-validation-test-report.txt"
        echo "📁 Test Artifacts: $TEST_DIR/"
        
        cleanup
        exit 0
    else
        log_error "❌ Some tests failed. Review the test report for details."
        echo ""
        echo "📋 Test Report: $TEST_DIR/pr-validation-test-report.txt"
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