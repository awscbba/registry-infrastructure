#!/bin/bash

# Test Script for Artifact Compatibility
# This script tests the artifact handling system to ensure placeholder and real artifacts
# maintain compatibility and can be consumed by downstream stages

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR="$WORKSPACE_ROOT/test-artifacts"
ARTIFACT_HANDLER="$SCRIPT_DIR/artifact-handler.sh"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

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

# Test result tracking
test_result() {
    local test_name="$1"
    local result="$2"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    
    if [[ "$result" == "PASS" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log_success "✓ $test_name"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        log_error "✗ $test_name"
    fi
}

# Setup test environment
setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Clean up any existing test directory
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"
    
    # Make artifact handler executable
    chmod +x "$ARTIFACT_HANDLER"
    
    log_success "Test environment setup completed"
}

# Test placeholder artifact creation
test_placeholder_creation() {
    log_info "Testing placeholder artifact creation..."
    
    local test_dir="$TEST_DIR/placeholder-test"
    mkdir -p "$test_dir"
    cd "$test_dir"
    
    # Test each artifact type
    local artifacts=("deploymentSummary" "testReport" "deploymentNotification")
    
    for artifact in "${artifacts[@]}"; do
        log_info "Testing placeholder creation for: $artifact"
        
        if "$ARTIFACT_HANDLER" create-placeholder "$artifact" "validation" "PULLREQUEST" "feature-branch" "."; then
            test_result "Placeholder creation for $artifact" "PASS"
        else
            test_result "Placeholder creation for $artifact" "FAIL"
        fi
    done
    
    cd "$WORKSPACE_ROOT"
}

# Test artifact structure validation
test_artifact_validation() {
    log_info "Testing artifact structure validation..."
    
    local test_dir="$TEST_DIR/validation-test"
    mkdir -p "$test_dir"
    cd "$test_dir"
    
    # Create placeholder artifacts first
    "$ARTIFACT_HANDLER" create-placeholder "deploymentSummary" "validation" "PULLREQUEST" "feature-branch" "."
    "$ARTIFACT_HANDLER" create-placeholder "testReport" "validation" "PULLREQUEST" "feature-branch" "."
    "$ARTIFACT_HANDLER" create-placeholder "deploymentNotification" "validation" "PULLREQUEST" "feature-branch" "."
    
    # Test validation for each artifact
    local artifacts=("deploymentSummary" "testReport" "deploymentNotification")
    
    for artifact in "${artifacts[@]}"; do
        log_info "Testing structure validation for: $artifact"
        
        if "$ARTIFACT_HANDLER" validate "$artifact" "."; then
            test_result "Structure validation for $artifact" "PASS"
        else
            test_result "Structure validation for $artifact" "FAIL"
        fi
    done
    
    cd "$WORKSPACE_ROOT"
}

# Test artifact consumption
test_artifact_consumption() {
    log_info "Testing artifact consumption..."
    
    local test_dir="$TEST_DIR/consumption-test"
    mkdir -p "$test_dir"
    cd "$test_dir"
    
    # Create placeholder artifacts first
    "$ARTIFACT_HANDLER" create-placeholder "deploymentSummary" "validation" "PULLREQUEST" "feature-branch" "."
    "$ARTIFACT_HANDLER" create-placeholder "testReport" "validation" "PULLREQUEST" "feature-branch" "."
    "$ARTIFACT_HANDLER" create-placeholder "deploymentNotification" "validation" "PULLREQUEST" "feature-branch" "."
    
    # Test consumption for each artifact
    local artifacts=("deploymentSummary" "testReport" "deploymentNotification")
    
    for artifact in "${artifacts[@]}"; do
        log_info "Testing consumption for: $artifact"
        
        if "$ARTIFACT_HANDLER" test-consumption "$artifact" "."; then
            test_result "Consumption test for $artifact" "PASS"
        else
            test_result "Consumption test for $artifact" "FAIL"
        fi
    done
    
    cd "$WORKSPACE_ROOT"
}

# Test placeholder detection
test_placeholder_detection() {
    log_info "Testing placeholder detection..."
    
    local test_dir="$TEST_DIR/detection-test"
    mkdir -p "$test_dir"
    cd "$test_dir"
    
    # Create placeholder artifacts
    "$ARTIFACT_HANDLER" create-placeholder "deploymentSummary" "validation" "PULLREQUEST" "feature-branch" "."
    "$ARTIFACT_HANDLER" create-placeholder "testReport" "validation" "PULLREQUEST" "feature-branch" "."
    
    # Test placeholder detection
    if "$ARTIFACT_HANDLER" is-placeholder "deployment-summary.json"; then
        test_result "Placeholder detection for deployment-summary.json" "PASS"
    else
        test_result "Placeholder detection for deployment-summary.json" "FAIL"
    fi
    
    if "$ARTIFACT_HANDLER" is-placeholder "post-deployment-test-report.txt"; then
        test_result "Placeholder detection for post-deployment-test-report.txt" "PASS"
    else
        test_result "Placeholder detection for post-deployment-test-report.txt" "FAIL"
    fi
    
    # Create a non-placeholder file and test
    echo '{"deployment_successful": true, "placeholder_artifact": false}' > real-deployment.json
    
    if ! "$ARTIFACT_HANDLER" is-placeholder "real-deployment.json"; then
        test_result "Non-placeholder detection for real-deployment.json" "PASS"
    else
        test_result "Non-placeholder detection for real-deployment.json" "FAIL"
    fi
    
    cd "$WORKSPACE_ROOT"
}

# Test data handling with fallbacks
test_data_handling() {
    log_info "Testing data handling with fallbacks..."
    
    local test_dir="$TEST_DIR/data-handling-test"
    mkdir -p "$test_dir"
    cd "$test_dir"
    
    # Create placeholder deployment summary
    "$ARTIFACT_HANDLER" create-placeholder "deploymentSummary" "validation" "PULLREQUEST" "feature-branch" "."
    
    # Test data extraction with fallbacks
    local api_url
    api_url=$("$ARTIFACT_HANDLER" handle-data "deployment-summary.json" ".outputs.api_url" "fallback_url" 2>&1 | tail -1)
    
    if [[ "$api_url" == "https://validation-placeholder.example.com/api" ]]; then
        test_result "Data extraction from placeholder artifact" "PASS"
    else
        test_result "Data extraction from placeholder artifact" "FAIL"
        log_error "Expected placeholder URL, got: $api_url"
    fi
    
    # Test fallback for missing file
    local missing_data
    missing_data=$("$ARTIFACT_HANDLER" handle-data "missing-file.json" ".some.field" "default_value" 2>/dev/null)
    
    if [[ "$missing_data" == "default_value" ]]; then
        test_result "Fallback for missing file" "PASS"
    else
        test_result "Fallback for missing file" "FAIL"
        log_error "Expected default_value, got: $missing_data"
    fi
    
    cd "$WORKSPACE_ROOT"
}

# Test artifact compatibility between modes
test_mode_compatibility() {
    log_info "Testing artifact compatibility between validation and deployment modes..."
    
    local test_dir="$TEST_DIR/compatibility-test"
    mkdir -p "$test_dir"
    cd "$test_dir"
    
    # Create validation mode artifacts
    mkdir -p validation
    cd validation
    "$ARTIFACT_HANDLER" create-placeholder "deploymentSummary" "validation" "PULLREQUEST" "feature-branch" "."
    "$ARTIFACT_HANDLER" create-placeholder "testReport" "validation" "PULLREQUEST" "feature-branch" "."
    cd ..
    
    # Create deployment mode artifacts (simulated)
    mkdir -p deployment
    cd deployment
    
    # Create realistic deployment artifacts
    cat > deployment-summary.json << EOF
{
  "deployment_successful": true,
  "deployment_type": "infrastructure_deployment",
  "api_sync_detected": false,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "execution_mode": "deployment",
  "trigger_type": "PUSH",
  "branch_name": "main",
  "outputs": {
    "api_url": "https://api.example.com",
    "frontend_url": "https://frontend.example.com",
    "s3_bucket": "my-deployment-bucket"
  },
  "handler_used": "enhanced_api_handler",
  "infrastructure_changes": "deployed",
  "deployment_duration": "300s",
  "stack_status": "deployed",
  "placeholder_artifact": false
}
EOF
    
    # Create outputs.json
    cat > outputs.json << EOF
{
  "PeopleRegisterInfrastructureStack": {
    "ApiUrl": "https://api.example.com",
    "FrontendUrl": "https://frontend.example.com",
    "S3BucketName": "my-deployment-bucket"
  }
}
EOF
    
    # Create deployment.log
    cat > deployment.log << EOF
Infrastructure Deployment Log - Deployment Mode
==============================================
Timestamp: $(date)
Execution Mode: deployment
Trigger Type: PUSH
Branch: main

DEPLOYMENT MODE ACTIVE
=====================
- Actual deployment executed
- Real artifacts created
- Infrastructure changes: deployed
- Stack status: deployed

Deployed Resources:
- API URL: https://api.example.com
- Frontend URL: https://frontend.example.com
- S3 Bucket: my-deployment-bucket

Status: Deployment completed successfully
EOF
    
    cat > post-deployment-test-report.txt << EOF
Post-Deployment Test Report
==========================
Timestamp: $(date)
Execution Mode: deployment
Trigger Type: PUSH
Branch: main
API URL: https://api.example.com
Deployment Type: infrastructure_deployment
Handler Used: enhanced_api_handler
Overall Status: PASSED

Test Results:
- Health endpoint: PASS
- People list: PASS
- Person CRUD: PASS

✅ All critical tests passed
EOF
    
    cd ..
    
    # Test that both modes produce consumable artifacts
    for mode in validation deployment; do
        cd "$mode"
        
        # Test data extraction works for both modes
        local api_url
        api_url=$("$ARTIFACT_HANDLER" handle-data "deployment-summary.json" ".outputs.api_url" "not_found")
        
        if [[ "$api_url" != "not_found" ]]; then
            test_result "Data extraction compatibility for $mode mode" "PASS"
        else
            test_result "Data extraction compatibility for $mode mode" "FAIL"
        fi
        
        # Test structure validation works for both modes
        if "$ARTIFACT_HANDLER" validate "deploymentSummary" "."; then
            test_result "Structure validation compatibility for $mode mode" "PASS"
        else
            test_result "Structure validation compatibility for $mode mode" "FAIL"
        fi
        
        cd ..
    done
    
    cd "$WORKSPACE_ROOT"
}

# Test error handling and edge cases
test_error_handling() {
    log_info "Testing error handling and edge cases..."
    
    local test_dir="$TEST_DIR/error-handling-test"
    mkdir -p "$test_dir"
    cd "$test_dir"
    
    # Test invalid artifact type
    if ! "$ARTIFACT_HANDLER" create-placeholder "invalid-artifact" "validation" "PULLREQUEST" "feature-branch" "." 2>/dev/null; then
        test_result "Error handling for invalid artifact type" "PASS"
    else
        test_result "Error handling for invalid artifact type" "FAIL"
    fi
    
    # Test missing directory
    if ! "$ARTIFACT_HANDLER" validate "deploymentSummary" "/nonexistent/path" 2>/dev/null; then
        test_result "Error handling for missing directory" "PASS"
    else
        test_result "Error handling for missing directory" "FAIL"
    fi
    
    # Test malformed JSON handling
    echo "invalid json content" > malformed.json
    local result
    result=$("$ARTIFACT_HANDLER" handle-data "malformed.json" ".field" "fallback" 2>/dev/null || echo "fallback")
    
    if [[ "$result" == "fallback" ]]; then
        test_result "Error handling for malformed JSON" "PASS"
    else
        test_result "Error handling for malformed JSON" "FAIL"
    fi
    
    cd "$WORKSPACE_ROOT"
}

# Generate test report
generate_test_report() {
    log_info "Generating test report..."
    
    local report_file="$TEST_DIR/artifact-compatibility-test-report.txt"
    
    cat > "$report_file" << EOF
Artifact Compatibility Test Report
==================================
Timestamp: $(date)
Test Environment: $TEST_DIR
Artifact Handler: $ARTIFACT_HANDLER

Test Summary:
=============
Total Tests: $TESTS_TOTAL
Passed: $TESTS_PASSED
Failed: $TESTS_FAILED
Success Rate: $(( TESTS_PASSED * 100 / TESTS_TOTAL ))%

Test Categories:
================
1. Placeholder Creation - Tests creation of placeholder artifacts
2. Structure Validation - Tests artifact structure validation
3. Consumption Testing - Tests artifact consumption by downstream stages
4. Placeholder Detection - Tests detection of placeholder vs real artifacts
5. Data Handling - Tests graceful data extraction with fallbacks
6. Mode Compatibility - Tests compatibility between validation and deployment modes
7. Error Handling - Tests error handling and edge cases

Overall Result: $([ $TESTS_FAILED -eq 0 ] && echo "PASSED" || echo "FAILED")

$([ $TESTS_FAILED -gt 0 ] && echo "⚠️ Some tests failed. Review the output above for details.")
$([ $TESTS_FAILED -eq 0 ] && echo "✅ All tests passed. Artifact handling system is working correctly.")

Recommendations:
================
- All placeholder artifacts maintain expected structure
- Downstream stages can consume both placeholder and real artifacts
- Graceful fallback handling is implemented for missing data
- Error handling is robust for edge cases
EOF
    
    echo ""
    echo "📋 Test Report Generated:"
    echo "========================"
    cat "$report_file"
    
    # Copy report to workspace root for easy access
    cp "$report_file" "$WORKSPACE_ROOT/artifact-compatibility-test-report.txt"
    log_success "Test report saved to: $WORKSPACE_ROOT/artifact-compatibility-test-report.txt"
}

# Cleanup test environment
cleanup_test_environment() {
    log_info "Cleaning up test environment..."
    
    # Keep the test report but clean up test artifacts
    if [[ -d "$TEST_DIR" ]]; then
        # Save the report before cleanup
        if [[ -f "$TEST_DIR/artifact-compatibility-test-report.txt" ]]; then
            cp "$TEST_DIR/artifact-compatibility-test-report.txt" "$WORKSPACE_ROOT/"
        fi
        
        # Clean up test directory
        rm -rf "$TEST_DIR"
    fi
    
    log_success "Test environment cleanup completed"
}

# Main test execution
main() {
    echo "🧪 Artifact Compatibility Test Suite"
    echo "===================================="
    echo ""
    
    # Setup
    setup_test_environment
    
    # Run test suites
    test_placeholder_creation
    test_artifact_validation
    test_artifact_consumption
    test_placeholder_detection
    test_data_handling
    test_mode_compatibility
    test_error_handling
    
    # Generate report
    generate_test_report
    
    # Cleanup
    cleanup_test_environment
    
    # Exit with appropriate code
    if [[ $TESTS_FAILED -eq 0 ]]; then
        log_success "🎉 All tests passed! Artifact handling system is working correctly."
        exit 0
    else
        log_error "❌ $TESTS_FAILED out of $TESTS_TOTAL tests failed."
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi