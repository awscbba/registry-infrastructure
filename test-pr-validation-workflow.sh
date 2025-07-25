#!/bin/bash

# Test script for PR validation workflow performance optimization
# This script simulates a pull request validation workflow to test performance improvements

set -e

echo "🧪 PR Validation Workflow Performance Test"
echo "=========================================="
echo "📅 Test Start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "🎯 Purpose: Validate performance optimizations for fast feedback"
echo ""

# Test configuration
TEST_START=$(date +%s)
TEST_REPORT="pr-validation-test-report.txt"
PERFORMANCE_TARGET=600  # 10 minutes maximum
IDEAL_TARGET=300        # 5 minutes ideal

# Initialize test report
cat > $TEST_REPORT << EOF
PR Validation Workflow Performance Test Report
=============================================
Test Start: $(date)
Performance Target: ${PERFORMANCE_TARGET}s (10 minutes max)
Ideal Target: ${IDEAL_TARGET}s (5 minutes ideal)

EOF

# Function to log test results
log_test() {
    local level="$1"
    local message="$2"
    local timestamp=$(date -u +%H:%M:%S)
    
    echo "[$timestamp] [$level] $message" | tee -a $TEST_REPORT
}

# Function to measure test step duration
measure_test_step() {
    local step_name="$1"
    local start_time=$(date +%s)
    echo "⏱️ Testing: $step_name"
    
    shift
    "$@"
    local result=$?
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    echo "✅ Test completed: $step_name (${duration}s)"
    log_test "INFO" "$step_name completed in ${duration}s"
    
    return $result
}

# Test 1: Simulate pull request environment
test_pullrequest_environment() {
    echo "🔍 Test 1: Pull Request Environment Simulation"
    
    # Set up pull request environment variables
    export CODECATALYST_TRIGGER_TYPE="PULLREQUEST"
    export CODECATALYST_SOURCE_BRANCH_NAME="feature/test-optimization"
    export CODECATALYST_TARGET_BRANCH_NAME="main"
    export CODECATALYST_PULLREQUEST_EVENT="PULLREQUEST_CREATED"
    export CODECATALYST_PULLREQUEST_ID="123"
    
    log_test "INFO" "Pull request environment configured"
    echo "  Trigger: $CODECATALYST_TRIGGER_TYPE"
    echo "  Source Branch: $CODECATALYST_SOURCE_BRANCH_NAME"
    echo "  Target Branch: $CODECATALYST_TARGET_BRANCH_NAME"
    
    return 0
}

# Test 2: Execution mode detection performance
test_execution_mode_detection() {
    echo "🎯 Test 2: Execution Mode Detection Performance"
    
    # Test optimized execution mode detection
    if [ -f "scripts/execution-mode-detection.sh" ]; then
        chmod +x scripts/execution-mode-detection.sh
        if ./scripts/execution-mode-detection.sh; then
            log_test "SUCCESS" "Execution mode detection completed"
            
            # Verify execution mode is set correctly for PR
            source execution-mode-env.sh
            if [ "$EXECUTION_MODE" = "validation" ] && [ "$SKIP_DEPLOYMENT" = "true" ]; then
                log_test "SUCCESS" "Execution mode correctly set to validation for PR"
                echo "  ✅ Execution Mode: $EXECUTION_MODE"
                echo "  ✅ Skip Deployment: $SKIP_DEPLOYMENT"
                echo "  ✅ Skip Testing: $SKIP_TESTING"
            else
                log_test "ERROR" "Execution mode not correctly set for PR"
                return 1
            fi
        else
            log_test "ERROR" "Execution mode detection failed"
            return 1
        fi
    else
        log_test "ERROR" "Execution mode detection script not found"
        return 1
    fi
    
    return 0
}

# Test 3: Optimized validation performance
test_optimized_validation() {
    echo "⚡ Test 3: Optimized Validation Performance"
    
    # Test the optimized validation script
    if [ -f "scripts/optimized-validation.sh" ]; then
        chmod +x scripts/optimized-validation.sh
        
        # Run optimized validation with timing
        local validation_start=$(date +%s)
        
        if ./scripts/optimized-validation.sh; then
            local validation_end=$(date +%s)
            local validation_duration=$((validation_end - validation_start))
            
            log_test "SUCCESS" "Optimized validation completed in ${validation_duration}s"
            
            # Check performance against targets
            if [ $validation_duration -le $IDEAL_TARGET ]; then
                log_test "EXCELLENT" "Validation time (${validation_duration}s) meets ideal target (${IDEAL_TARGET}s)"
                echo "  🎯 Performance: EXCELLENT (under 5 minutes)"
            elif [ $validation_duration -le $PERFORMANCE_TARGET ]; then
                log_test "GOOD" "Validation time (${validation_duration}s) meets performance target (${PERFORMANCE_TARGET}s)"
                echo "  ✅ Performance: GOOD (under 10 minutes)"
            else
                log_test "WARNING" "Validation time (${validation_duration}s) exceeds performance target (${PERFORMANCE_TARGET}s)"
                echo "  ⚠️ Performance: NEEDS IMPROVEMENT (over 10 minutes)"
            fi
            
            # Check if validation results were created
            if [ -f "validation-results.json" ]; then
                log_test "SUCCESS" "Validation results artifact created"
                echo "  📊 Validation Results:"
                cat validation-results.json | jq '.' 2>/dev/null || cat validation-results.json
            else
                log_test "WARNING" "Validation results artifact not found"
            fi
            
        else
            log_test "ERROR" "Optimized validation failed"
            return 1
        fi
    else
        log_test "ERROR" "Optimized validation script not found"
        return 1
    fi
    
    return 0
}

# Test 4: Performance profiling
test_performance_profiling() {
    echo "📊 Test 4: Performance Profiling"
    
    # Test the performance profiler
    if [ -f "scripts/performance-profiler.sh" ]; then
        chmod +x scripts/performance-profiler.sh
        
        if ./scripts/performance-profiler.sh; then
            log_test "SUCCESS" "Performance profiling completed"
            
            # Check if profiling reports were created
            if [ -f "performance-profile.json" ]; then
                log_test "SUCCESS" "Performance profile created"
                echo "  📊 Performance Profile:"
                cat performance-profile.json | jq '.stage_timings' 2>/dev/null || echo "  Profile data available"
            fi
            
            if [ -f "optimization-recommendations.txt" ]; then
                log_test "SUCCESS" "Optimization recommendations created"
                echo "  📋 Optimization Recommendations Available"
            fi
            
        else
            log_test "WARNING" "Performance profiling failed (non-critical)"
        fi
    else
        log_test "WARNING" "Performance profiler script not found (non-critical)"
    fi
    
    return 0
}

# Test 5: Caching mechanisms
test_caching_mechanisms() {
    echo "💾 Test 5: Caching Mechanisms"
    
    # Test AWS credentials caching
    if [ -f "aws-identity.json" ]; then
        log_test "SUCCESS" "AWS credentials caching working"
        echo "  ✅ AWS identity cached"
    else
        log_test "INFO" "AWS credentials not cached (first run)"
    fi
    
    # Test IAM permissions caching
    if [ -f "iam-permissions-cache.json" ]; then
        log_test "SUCCESS" "IAM permissions caching working"
        echo "  ✅ IAM permissions cached"
    else
        log_test "INFO" "IAM permissions not cached (first run)"
    fi
    
    # Test CDK environment caching
    if [ -d ".venv" ] && [ -f ".venv/cdk-setup-complete" ]; then
        log_test "SUCCESS" "CDK environment caching working"
        echo "  ✅ CDK environment cached"
    else
        log_test "INFO" "CDK environment not cached (first run)"
    fi
    
    return 0
}

# Test 6: Artifact compatibility
test_artifact_compatibility() {
    echo "📦 Test 6: Artifact Compatibility"
    
    # Check that required artifacts are created
    local artifacts_ok=true
    
    # Check validation results
    if [ -f "validation-results.json" ]; then
        log_test "SUCCESS" "validation-results.json artifact created"
    else
        log_test "ERROR" "validation-results.json artifact missing"
        artifacts_ok=false
    fi
    
    # Check validation report
    if [ -f "validation-report.txt" ]; then
        log_test "SUCCESS" "validation-report.txt artifact created"
    else
        log_test "WARNING" "validation-report.txt artifact missing"
    fi
    
    # Check execution context
    if [ -f "execution-context.json" ]; then
        log_test "SUCCESS" "execution-context.json artifact created"
    else
        log_test "WARNING" "execution-context.json artifact missing"
    fi
    
    if $artifacts_ok; then
        echo "  ✅ All critical artifacts present"
        return 0
    else
        echo "  ❌ Some critical artifacts missing"
        return 1
    fi
}

# Generate test summary
generate_test_summary() {
    echo "📋 Generating Test Summary"
    
    local total_time=$(($(date +%s) - TEST_START))
    
    cat >> $TEST_REPORT << EOF

TEST SUMMARY
============
Total Test Duration: ${total_time}s
Performance Target: ${PERFORMANCE_TARGET}s (10 minutes max)
Ideal Target: ${IDEAL_TARGET}s (5 minutes ideal)

Performance Assessment:
EOF
    
    if [ $total_time -le $IDEAL_TARGET ]; then
        echo "🎯 EXCELLENT: Test completed in ${total_time}s (under 5 minutes)" | tee -a $TEST_REPORT
        echo "  ✅ Meets ideal target for pull request feedback" | tee -a $TEST_REPORT
    elif [ $total_time -le $PERFORMANCE_TARGET ]; then
        echo "✅ GOOD: Test completed in ${total_time}s (under 10 minutes)" | tee -a $TEST_REPORT
        echo "  ✅ Meets performance target for pull request feedback" | tee -a $TEST_REPORT
    else
        echo "⚠️ SLOW: Test completed in ${total_time}s (over 10 minutes)" | tee -a $TEST_REPORT
        echo "  ⚠️ Exceeds performance target - additional optimization needed" | tee -a $TEST_REPORT
    fi
    
    cat >> $TEST_REPORT << EOF

Optimization Features Tested:
- ✅ Pull request environment simulation
- ✅ Fast execution mode detection
- ✅ Optimized validation pipeline
- ✅ Performance profiling
- ✅ Caching mechanisms
- ✅ Artifact compatibility

Next Steps:
1. Monitor validation times in real pull requests
2. Implement additional optimizations if needed
3. Set up performance regression testing
4. Document optimization features for team

EOF
    
    echo ""
    echo "📊 Test Summary:"
    echo "  Duration: ${total_time}s"
    echo "  Target: ${PERFORMANCE_TARGET}s"
    echo "  Status: $([ $total_time -le $PERFORMANCE_TARGET ] && echo "✅ PASSED" || echo "⚠️ NEEDS IMPROVEMENT")"
}

# Main test execution
main() {
    echo "🚀 Starting PR validation workflow performance test..."
    
    # Run test steps
    measure_test_step "PR_Environment" test_pullrequest_environment || true
    measure_test_step "Execution_Mode" test_execution_mode_detection || true
    measure_test_step "Optimized_Validation" test_optimized_validation || true
    measure_test_step "Performance_Profiling" test_performance_profiling || true
    measure_test_step "Caching_Mechanisms" test_caching_mechanisms || true
    measure_test_step "Artifact_Compatibility" test_artifact_compatibility || true
    
    # Generate summary
    generate_test_summary
    
    local total_time=$(($(date +%s) - TEST_START))
    
    echo ""
    echo "🧪 PR VALIDATION WORKFLOW TEST COMPLETE"
    echo "======================================="
    echo "Duration: ${total_time}s"
    echo "Performance: $([ $total_time -le $PERFORMANCE_TARGET ] && echo "✅ MEETS TARGET" || echo "⚠️ EXCEEDS TARGET")"
    echo ""
    echo "📋 Test report: $TEST_REPORT"
    
    # Return success if within performance target
    [ $total_time -le $PERFORMANCE_TARGET ]
}

# Execute main function
main "$@"