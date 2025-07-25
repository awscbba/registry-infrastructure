#!/bin/bash

# Optimized Infrastructure Validation Script
# This script provides fast validation feedback for pull requests (target: 5-10 minutes)

set -e

echo "⚡ Optimized Infrastructure Validation"
echo "===================================="
echo "📅 Stage Start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "🎯 Target: Fast feedback within 5-10 minutes"
echo ""

# Performance tracking
VALIDATION_START=$(date +%s)
VALIDATION_ERRORS=0
VALIDATION_WARNINGS=0
VALIDATION_REPORT="validation-report.txt"

# Source execution mode (should be cached from previous stage)
source execution-mode-env.sh 2>/dev/null || {
    echo "⚠️ Execution mode not cached, using fast detection"
    EXECUTION_MODE="validation"
    SKIP_DEPLOYMENT="true"
    SKIP_TESTING="true"
}

echo "📊 Optimized Validation Context:"
echo "  Execution Mode: $EXECUTION_MODE"
echo "  Target Duration: 5-10 minutes"
echo "  Optimization Level: HIGH"
echo ""

# Initialize validation report
cat > $VALIDATION_REPORT << EOF
Optimized Infrastructure Validation Report
=========================================
Timestamp: $(date)
Execution Mode: $EXECUTION_MODE
Optimization Level: HIGH
Target Duration: 5-10 minutes

EOF

# Function to log validation results with timing
log_validation() {
    local level="$1"
    local message="$2"
    local suggestion="${3:-}"
    local timestamp=$(date -u +%H:%M:%S)
    
    echo "[$timestamp] [$level] $message" | tee -a $VALIDATION_REPORT
    if [ -n "$suggestion" ]; then
        echo "[$timestamp]   💡 $suggestion" | tee -a $VALIDATION_REPORT
    fi
    
    case "$level" in
        "ERROR") VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1)) ;;
        "WARNING") VALIDATION_WARNINGS=$((VALIDATION_WARNINGS + 1)) ;;
    esac
}

# Function to measure step duration
measure_step() {
    local step_name="$1"
    local start_time=$(date +%s)
    echo "⏱️ [$step_name] Starting..."
    
    shift
    "$@"
    local result=$?
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    echo "✅ [$step_name] Completed in ${duration}s"
    
    return $result
}

# Step 1: Fast AWS Credentials Validation
fast_aws_credentials_validation() {
    echo "🔐 Fast AWS Credentials Validation"
    
    # Use cached identity if available and recent (< 5 minutes)
    if [ -f "aws-identity.json" ] && [ $(($(date +%s) - $(stat -c %Y aws-identity.json 2>/dev/null || echo 0))) -lt 300 ]; then
        ACCOUNT_ID=$(jq -r '.Account' aws-identity.json 2>/dev/null || echo "cached")
        echo "✅ Using cached AWS identity: $ACCOUNT_ID"
        log_validation "INFO" "AWS credentials validated (cached)"
        return 0
    fi
    
    # Fast credentials check with timeout
    if timeout 30 aws sts get-caller-identity > aws-identity.json 2>&1; then
        ACCOUNT_ID=$(jq -r '.Account' aws-identity.json)
        echo "✅ AWS credentials validated: $ACCOUNT_ID"
        log_validation "INFO" "AWS credentials validated successfully"
        return 0
    else
        echo "❌ AWS credentials validation failed"
        log_validation "ERROR" "AWS credentials validation failed" "Check AWS credentials and permissions"
        return 1
    fi
}

# Step 2: Parallel IAM Permissions Check
parallel_iam_permissions_check() {
    echo "🔑 Parallel IAM Permissions Check"
    
    # Use cached permissions if available and recent (< 10 minutes)
    if [ -f "iam-permissions-cache.json" ] && [ $(($(date +%s) - $(stat -c %Y iam-permissions-cache.json 2>/dev/null || echo 0))) -lt 600 ]; then
        echo "✅ Using cached IAM permissions"
        log_validation "INFO" "IAM permissions validated (cached)"
        return 0
    fi
    
    echo "Running parallel permission checks..."
    
    # Create temporary files for parallel results
    local temp_dir=$(mktemp -d)
    
    # Run permission checks in parallel with timeouts
    {
        timeout 15 aws dynamodb describe-limits --region us-east-1 >/dev/null 2>&1 && echo "ok" > "$temp_dir/dynamodb" || echo "fail" > "$temp_dir/dynamodb"
    } &
    
    {
        timeout 15 aws lambda list-functions --max-items 1 >/dev/null 2>&1 && echo "ok" > "$temp_dir/lambda" || echo "fail" > "$temp_dir/lambda"
    } &
    
    {
        timeout 15 aws s3api list-buckets >/dev/null 2>&1 && echo "ok" > "$temp_dir/s3" || echo "fail" > "$temp_dir/s3"
    } &
    
    # Wait for all parallel checks to complete
    wait
    
    # Check results
    local permission_errors=0
    for service in dynamodb lambda s3; do
        if [ "$(cat "$temp_dir/$service" 2>/dev/null)" = "ok" ]; then
            echo "  ✅ $service permissions: OK"
            log_validation "INFO" "$service permissions validated"
        else
            echo "  ❌ $service permissions: FAILED"
            log_validation "ERROR" "$service permissions insufficient" "Ensure role has $service permissions"
            permission_errors=$((permission_errors + 1))
        fi
    done
    
    # Cache results for future use
    echo "{\"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"status\": \"checked\"}" > iam-permissions-cache.json
    
    # Cleanup
    rm -rf "$temp_dir"
    
    if [ $permission_errors -eq 0 ]; then
        echo "✅ All IAM permissions validated"
        return 0
    else
        echo "❌ IAM permission validation failed ($permission_errors errors)"
        return 1
    fi
}

# Step 3: Fast Resource Configuration Validation
fast_resource_configuration_validation() {
    echo "🏗️ Fast Resource Configuration Validation"
    
    local config_errors=0
    
    # Check CDK stack file
    if [ -f "people_register_infrastructure/people_register_infrastructure_stack.py" ]; then
        echo "  ✅ CDK stack file found"
        log_validation "INFO" "CDK stack configuration file found"
        
        # Fast configuration checks
        if grep -q "PYTHON_3_11" people_register_infrastructure/people_register_infrastructure_stack.py; then
            echo "  ⚠️ PYTHON_3_11 runtime detected (will be auto-fixed)"
            log_validation "WARNING" "Lambda runtime will be updated to PYTHON_3_9"
        fi
    else
        echo "  ❌ CDK stack file missing"
        log_validation "ERROR" "CDK stack configuration file missing"
        config_errors=$((config_errors + 1))
    fi
    
    # Parallel Lambda handler validation
    echo "  🔍 Validating Lambda handlers..."
    local handler_pids=()
    
    for handler in enhanced_api_handler.py auth_handler.py; do
        {
            if [ -f "lambda/$handler" ]; then
                # Fast AST-based syntax check (faster than py_compile)
                if python3 -m ast "lambda/$handler" 2>/dev/null; then
                    echo "    ✅ $handler: syntax OK"
                else
                    echo "    ❌ $handler: syntax error"
                    config_errors=$((config_errors + 1))
                fi
            else
                echo "    ❌ $handler: missing"
                config_errors=$((config_errors + 1))
            fi
        } &
        handler_pids+=($!)
    done
    
    # Wait for handler validation to complete
    for pid in "${handler_pids[@]}"; do
        wait $pid
    done
    
    # Check requirements.txt
    if [ -f "lambda/requirements.txt" ]; then
        echo "  ✅ Lambda requirements.txt found"
        log_validation "INFO" "Lambda requirements.txt validated"
    else
        echo "  ❌ Lambda requirements.txt missing"
        log_validation "ERROR" "Lambda requirements.txt missing"
        config_errors=$((config_errors + 1))
    fi
    
    if [ $config_errors -eq 0 ]; then
        echo "✅ Resource configuration validated"
        return 0
    else
        echo "❌ Resource configuration validation failed ($config_errors errors)"
        return 1
    fi
}

# Step 4: Optimized CDK Environment Setup
optimized_cdk_environment_setup() {
    echo "⚙️ Optimized CDK Environment Setup"
    
    # Check for cached environment
    if [ -d ".venv" ] && [ -f ".venv/bin/activate" ] && [ -f ".venv/cdk-setup-complete" ]; then
        echo "✅ Using cached CDK environment"
        source .venv/bin/activate
        log_validation "INFO" "CDK environment loaded from cache"
        return 0
    fi
    
    echo "🔄 Setting up fresh CDK environment..."
    
    # Create virtual environment
    python3 -m venv .venv
    source .venv/bin/activate
    
    # Install minimal required packages for validation
    echo "📦 Installing essential CDK packages..."
    pip install --quiet --no-cache-dir --disable-pip-version-check \
        aws-cdk-lib==2.80.0 \
        constructs>=10.0.0,\<11.0.0 \
        boto3>=1.34.0
    
    # Install CDK CLI if not available globally
    if ! command -v cdk >/dev/null 2>&1; then
        echo "📦 Installing CDK CLI..."
        npm install -g --silent aws-cdk@2.80.0
    fi
    
    # Mark setup as complete for caching
    touch .venv/cdk-setup-complete
    
    echo "✅ CDK environment setup completed"
    log_validation "INFO" "CDK environment setup completed"
    return 0
}

# Step 5: Fast CDK Synthesis Validation
fast_cdk_synthesis_validation() {
    echo "⚙️ Fast CDK Synthesis Validation"
    
    # Apply runtime compatibility fixes
    if [ -f "people_register_infrastructure/people_register_infrastructure_stack.py" ]; then
        if grep -q "PYTHON_3_11" people_register_infrastructure/people_register_infrastructure_stack.py; then
            echo "🔧 Applying runtime compatibility fix..."
            sed -i 's/runtime=_lambda\.Runtime\.PYTHON_3_11/runtime=_lambda.Runtime.PYTHON_3_9/g' \
                people_register_infrastructure/people_register_infrastructure_stack.py
            log_validation "INFO" "Lambda runtime updated to PYTHON_3_9"
        fi
    fi
    
    # Update handler reference if API sync detected
    API_SYNC_DETECTED=$(jq -r '.api_sync_detected // false' deployment-context.json 2>/dev/null || echo "false")
    if [ "$API_SYNC_DETECTED" = "true" ] && [ -f "lambda/integrated_api_handler.py" ]; then
        echo "🔧 Updating CDK stack for integrated API handler..."
        sed -i 's/handler="enhanced_api_handler.lambda_handler"/handler="integrated_api_handler.lambda_handler"/g' \
            people_register_infrastructure/people_register_infrastructure_stack.py
        log_validation "INFO" "CDK stack updated for integrated API handler"
    fi
    
    # Fast CDK synthesis with minimal output
    echo "🔄 Performing CDK synthesis..."
    source .venv/bin/activate
    
    if timeout 120 cdk synth --quiet --no-version-reporting --no-staging > /dev/null 2>cdk-synth-errors.txt; then
        echo "✅ CDK synthesis successful"
        log_validation "INFO" "CDK synthesis completed successfully"
        
        # Quick template analysis (only if synthesis succeeded)
        if [ -f "cdk.out/PeopleRegisterInfrastructureStack.template.json" ]; then
            TEMPLATE_SIZE=$(wc -c < "cdk.out/PeopleRegisterInfrastructureStack.template.json")
            RESOURCE_COUNT=$(jq '.Resources | length' "cdk.out/PeopleRegisterInfrastructureStack.template.json" 2>/dev/null || echo "0")
            
            echo "  📊 Template: ${TEMPLATE_SIZE} bytes, ${RESOURCE_COUNT} resources"
            log_validation "INFO" "CloudFormation template: ${TEMPLATE_SIZE} bytes, ${RESOURCE_COUNT} resources"
            
            # Check for size warnings
            if [ $TEMPLATE_SIZE -gt 51200 ]; then
                log_validation "WARNING" "Template size (${TEMPLATE_SIZE} bytes) exceeds 51KB limit" "Will use S3 upload during deployment"
            fi
        fi
        
        return 0
    else
        echo "❌ CDK synthesis failed"
        log_validation "ERROR" "CDK synthesis failed" "Review CDK stack configuration"
        
        # Provide concise error analysis
        if [ -f "cdk-synth-errors.txt" ] && [ -s "cdk-synth-errors.txt" ]; then
            echo "🔍 Synthesis errors:"
            head -10 cdk-synth-errors.txt | sed 's/^/  /'
            
            # Quick error pattern analysis
            if grep -q "ModuleNotFoundError" cdk-synth-errors.txt; then
                log_validation "ERROR" "Python module import error" "Check virtual environment setup"
            elif grep -q "ValidationError" cdk-synth-errors.txt; then
                log_validation "ERROR" "CDK validation error" "Review construct configuration"
            fi
        fi
        
        return 1
    fi
}

# Step 6: Generate Validation Summary
generate_validation_summary() {
    echo "📋 Generating Validation Summary"
    
    local total_time=$(($(date +%s) - VALIDATION_START))
    local target_time=600  # 10 minutes maximum
    
    # Add summary to report
    cat >> $VALIDATION_REPORT << EOF

VALIDATION SUMMARY
==================
Total Duration: ${total_time}s
Target Duration: ${target_time}s (10 minutes max)
Performance: $([ $total_time -le $target_time ] && echo "✅ WITHIN TARGET" || echo "⚠️ EXCEEDS TARGET")

Results:
- Errors: $VALIDATION_ERRORS
- Warnings: $VALIDATION_WARNINGS
- Status: $([ $VALIDATION_ERRORS -eq 0 ] && echo "SUCCESS" || echo "FAILED")

Optimization Features Used:
- ✅ Cached AWS credentials validation
- ✅ Parallel IAM permissions checking
- ✅ Fast resource configuration validation
- ✅ Cached CDK environment setup
- ✅ Optimized CDK synthesis with timeouts
- ✅ Minimal logging for speed

EOF
    
    # Create validation results JSON
    cat > validation-results.json << EOF
{
  "status": "$([ $VALIDATION_ERRORS -eq 0 ] && echo "success" || echo "failed")",
  "errors": $VALIDATION_ERRORS,
  "warnings": $VALIDATION_WARNINGS,
  "duration": $total_time,
  "target_duration": $target_time,
  "performance_ratio": $(echo "scale=2; $target_time / $total_time" | bc 2>/dev/null || echo "1.0"),
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "execution_mode": "$EXECUTION_MODE",
  "optimization_level": "HIGH",
  "features_used": [
    "cached_credentials",
    "parallel_permissions",
    "fast_config_validation",
    "cached_cdk_environment",
    "optimized_synthesis"
  ]
}
EOF
    
    echo "📊 Validation completed in ${total_time}s (target: ${target_time}s)"
    
    if [ $total_time -le 300 ]; then
        echo "🎯 EXCELLENT: Under 5 minutes - ideal for pull request feedback"
    elif [ $total_time -le 600 ]; then
        echo "✅ GOOD: Under 10 minutes - acceptable for pull request feedback"
    else
        echo "⚠️ SLOW: Over 10 minutes - consider additional optimizations"
    fi
}

# Main execution
main() {
    echo "🚀 Starting optimized validation..."
    
    # Execute validation steps with timing
    measure_step "AWS_Credentials" fast_aws_credentials_validation || true
    measure_step "IAM_Permissions" parallel_iam_permissions_check || true
    measure_step "Resource_Config" fast_resource_configuration_validation || true
    measure_step "CDK_Environment" optimized_cdk_environment_setup || true
    measure_step "CDK_Synthesis" fast_cdk_synthesis_validation || true
    measure_step "Summary" generate_validation_summary
    
    local total_time=$(($(date +%s) - VALIDATION_START))
    
    echo ""
    echo "⚡ OPTIMIZED VALIDATION COMPLETE"
    echo "==============================="
    echo "Duration: ${total_time}s"
    echo "Errors: $VALIDATION_ERRORS"
    echo "Warnings: $VALIDATION_WARNINGS"
    echo "Status: $([ $VALIDATION_ERRORS -eq 0 ] && echo "✅ SUCCESS" || echo "❌ FAILED")"
    echo ""
    
    # Performance feedback
    if [ $total_time -le 300 ]; then
        echo "🎯 Performance: EXCELLENT (under 5 minutes)"
    elif [ $total_time -le 600 ]; then
        echo "✅ Performance: GOOD (under 10 minutes)"
    else
        echo "⚠️ Performance: NEEDS IMPROVEMENT (over 10 minutes)"
    fi
    
    # Exit with appropriate code
    [ $VALIDATION_ERRORS -eq 0 ]
}

# Execute main function
main "$@"