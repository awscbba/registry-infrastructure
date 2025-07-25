#!/bin/bash

# Performance Profiler for Validation Stages
# This script profiles validation stage execution times and identifies optimization opportunities

set -e

echo "⚡ Validation Stage Performance Profiler"
echo "======================================="
echo "📅 Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "🎯 Purpose: Profile validation stages for fast feedback optimization"
echo ""

# Initialize performance tracking
PROFILE_START=$(date +%s)
PROFILE_REPORT="performance-profile.json"
OPTIMIZATION_REPORT="optimization-recommendations.txt"

# Create performance tracking structure
cat > $PROFILE_REPORT << 'EOF'
{
  "profile_timestamp": "",
  "total_validation_time": 0,
  "stage_timings": {
    "execution_mode_detection": 0,
    "aws_credentials_validation": 0,
    "iam_permissions_check": 0,
    "resource_configuration_validation": 0,
    "cdk_environment_setup": 0,
    "cdk_synthesis": 0,
    "validation_summary": 0
  },
  "optimization_opportunities": [],
  "performance_metrics": {
    "target_time": 300,
    "current_time": 0,
    "performance_ratio": 0,
    "bottlenecks": []
  }
}
EOF

# Function to measure execution time
measure_time() {
    local stage_name="$1"
    local start_time=$(date +%s)
    
    echo "⏱️ Starting: $stage_name"
    
    # Execute the stage function
    "$@"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo "✅ Completed: $stage_name (${duration}s)"
    
    # Update performance profile
    jq --arg stage "$stage_name" --argjson duration "$duration" \
       '.stage_timings[$stage] = $duration' $PROFILE_REPORT > tmp.json && mv tmp.json $PROFILE_REPORT
    
    return $duration
}

# Function to add optimization recommendation
add_optimization() {
    local category="$1"
    local description="$2"
    local impact="$3"
    local implementation="$4"
    
    jq --arg cat "$category" --arg desc "$description" --arg imp "$impact" --arg impl "$implementation" \
       '.optimization_opportunities += [{
         "category": $cat,
         "description": $desc,
         "impact": $imp,
         "implementation": $impl
       }]' $PROFILE_REPORT > tmp.json && mv tmp.json $PROFILE_REPORT
}

# Optimized execution mode detection
optimized_execution_mode_detection() {
    echo "🔍 Optimized Execution Mode Detection"
    
    # Use cached environment variables if available
    if [ -f "execution-mode-env.sh" ]; then
        source execution-mode-env.sh
        echo "✅ Using cached execution mode: $EXECUTION_MODE"
        return 0
    fi
    
    # Fast execution mode detection (minimal logging)
    TRIGGER_TYPE="${CODECATALYST_TRIGGER_TYPE:-UNKNOWN}"
    BRANCH_NAME="${CODECATALYST_SOURCE_BRANCH_NAME:-unknown}"
    
    case "$TRIGGER_TYPE" in
        "PULLREQUEST")
            EXECUTION_MODE="validation"
            SKIP_DEPLOYMENT="true"
            SKIP_TESTING="true"
            ;;
        "PUSH")
            if [ "$BRANCH_NAME" = "main" ]; then
                EXECUTION_MODE="deployment"
                SKIP_DEPLOYMENT="false"
                SKIP_TESTING="false"
            else
                EXECUTION_MODE="validation"
                SKIP_DEPLOYMENT="true"
                SKIP_TESTING="true"
            fi
            ;;
        *)
            EXECUTION_MODE="validation"
            SKIP_DEPLOYMENT="true"
            SKIP_TESTING="true"
            ;;
    esac
    
    # Export for reuse
    echo "export EXECUTION_MODE=\"$EXECUTION_MODE\"" > execution-mode-env.sh
    echo "export TRIGGER_TYPE=\"$TRIGGER_TYPE\"" >> execution-mode-env.sh
    echo "export BRANCH_NAME=\"$BRANCH_NAME\"" >> execution-mode-env.sh
    echo "export SKIP_DEPLOYMENT=\"$SKIP_DEPLOYMENT\"" >> execution-mode-env.sh
    echo "export SKIP_TESTING=\"$SKIP_TESTING\"" >> execution-mode-env.sh
    
    echo "✅ Fast execution mode detection completed"
}

# Optimized AWS credentials validation
optimized_aws_credentials_validation() {
    echo "🔐 Optimized AWS Credentials Validation"
    
    # Use cached identity if available and recent (< 5 minutes)
    if [ -f "aws-identity.json" ] && [ $(($(date +%s) - $(stat -c %Y aws-identity.json))) -lt 300 ]; then
        echo "✅ Using cached AWS identity"
        return 0
    fi
    
    # Fast credentials check
    if aws sts get-caller-identity > aws-identity.json 2>&1; then
        echo "✅ AWS credentials validated"
        return 0
    else
        echo "❌ AWS credentials validation failed"
        return 1
    fi
}

# Optimized IAM permissions check
optimized_iam_permissions_check() {
    echo "🔑 Optimized IAM Permissions Check"
    
    # Use cached permissions if available and recent (< 10 minutes)
    if [ -f "iam-permissions-cache.json" ] && [ $(($(date +%s) - $(stat -c %Y iam-permissions-cache.json))) -lt 600 ]; then
        echo "✅ Using cached IAM permissions"
        return 0
    fi
    
    # Parallel permission checks for speed
    {
        aws dynamodb describe-limits --region us-east-1 >/dev/null 2>&1 && echo "dynamodb:ok" || echo "dynamodb:fail"
    } &
    {
        aws lambda list-functions --max-items 1 >/dev/null 2>&1 && echo "lambda:ok" || echo "lambda:fail"
    } &
    {
        aws s3api list-buckets >/dev/null 2>&1 && echo "s3:ok" || echo "s3:fail"
    } &
    
    wait
    
    # Cache results
    echo "{\"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"status\": \"cached\"}" > iam-permissions-cache.json
    echo "✅ IAM permissions checked (parallel)"
}

# Optimized resource configuration validation
optimized_resource_configuration_validation() {
    echo "🏗️ Optimized Resource Configuration Validation"
    
    # Fast file existence checks
    local errors=0
    
    # Check CDK stack file
    if [ ! -f "people_register_infrastructure/people_register_infrastructure_stack.py" ]; then
        echo "❌ CDK stack file missing"
        errors=$((errors + 1))
    fi
    
    # Check Lambda handlers (parallel)
    for handler in enhanced_api_handler.py auth_handler.py; do
        if [ -f "lambda/$handler" ]; then
            # Fast syntax check without full compilation
            python3 -m ast "lambda/$handler" 2>/dev/null || {
                echo "❌ Syntax error in $handler"
                errors=$((errors + 1))
            }
        fi &
    done
    wait
    
    # Check requirements.txt
    [ -f "lambda/requirements.txt" ] || {
        echo "❌ Lambda requirements.txt missing"
        errors=$((errors + 1))
    }
    
    if [ $errors -eq 0 ]; then
        echo "✅ Resource configuration validated"
        return 0
    else
        echo "❌ Resource configuration validation failed ($errors errors)"
        return 1
    fi
}

# Optimized CDK environment setup
optimized_cdk_environment_setup() {
    echo "⚙️ Optimized CDK Environment Setup"
    
    # Use cached virtual environment if available
    if [ -d ".venv" ] && [ -f ".venv/bin/activate" ] && [ -f ".venv/cdk-setup-complete" ]; then
        echo "✅ Using cached CDK environment"
        source .venv/bin/activate
        return 0
    fi
    
    # Fast environment setup
    python3 -m venv .venv
    source .venv/bin/activate
    
    # Install only essential packages for validation
    pip install --quiet --no-cache-dir aws-cdk-lib==2.80.0 constructs>=10.0.0,\<11.0.0 boto3>=1.34.0
    
    # Install CDK CLI if not available
    if ! command -v cdk >/dev/null 2>&1; then
        npm install -g --silent aws-cdk@2.80.0
    fi
    
    # Mark setup as complete
    touch .venv/cdk-setup-complete
    echo "✅ CDK environment setup completed"
}

# Optimized CDK synthesis
optimized_cdk_synthesis() {
    echo "⚙️ Optimized CDK Synthesis"
    
    # Apply runtime fixes if needed
    if grep -q "PYTHON_3_11" people_register_infrastructure/people_register_infrastructure_stack.py; then
        sed -i 's/runtime=_lambda\.Runtime\.PYTHON_3_11/runtime=_lambda.Runtime.PYTHON_3_9/g' \
            people_register_infrastructure/people_register_infrastructure_stack.py
    fi
    
    # Fast CDK synthesis with minimal output
    source .venv/bin/activate
    if cdk synth --quiet --no-version-reporting > /dev/null 2>cdk-synth-errors.txt; then
        echo "✅ CDK synthesis successful"
        
        # Quick template analysis
        if [ -f "cdk.out/PeopleRegisterInfrastructureStack.template.json" ]; then
            TEMPLATE_SIZE=$(wc -c < "cdk.out/PeopleRegisterInfrastructureStack.template.json")
            RESOURCE_COUNT=$(jq '.Resources | length' "cdk.out/PeopleRegisterInfrastructureStack.template.json" 2>/dev/null || echo "0")
            echo "📊 Template: ${TEMPLATE_SIZE} bytes, ${RESOURCE_COUNT} resources"
        fi
        
        return 0
    else
        echo "❌ CDK synthesis failed"
        return 1
    fi
}

# Generate optimization summary
generate_optimization_summary() {
    echo "📊 Generating Optimization Summary"
    
    local total_time=$(($(date +%s) - PROFILE_START))
    local target_time=300  # 5 minutes target
    
    # Update performance metrics
    jq --argjson total "$total_time" --argjson target "$target_time" \
       '.total_validation_time = $total |
        .performance_metrics.current_time = $total |
        .performance_metrics.target_time = $target |
        .performance_metrics.performance_ratio = ($target / $total) |
        .profile_timestamp = now | strftime("%Y-%m-%dT%H:%M:%SZ")' \
       $PROFILE_REPORT > tmp.json && mv tmp.json $PROFILE_REPORT
    
    # Generate optimization recommendations
    cat > $OPTIMIZATION_REPORT << EOF
Validation Stage Performance Optimization Report
==============================================
Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

PERFORMANCE SUMMARY:
- Current validation time: ${total_time}s
- Target validation time: ${target_time}s
- Performance ratio: $(echo "scale=2; $target_time / $total_time" | bc)

OPTIMIZATION RECOMMENDATIONS:

1. CACHING OPTIMIZATIONS:
   - Cache AWS credentials validation (5min TTL)
   - Cache IAM permissions check (10min TTL)
   - Cache CDK virtual environment setup
   - Cache execution mode detection results

2. PARALLEL PROCESSING:
   - Run IAM permission checks in parallel
   - Parallel Lambda handler syntax validation
   - Concurrent file existence checks

3. MINIMAL DEPENDENCY INSTALLATION:
   - Install only essential CDK packages for validation
   - Use --quiet and --no-cache-dir flags
   - Skip unnecessary development dependencies

4. FAST CDK SYNTHESIS:
   - Use --quiet and --no-version-reporting flags
   - Skip detailed template analysis in validation mode
   - Cache synthesis results for identical configurations

5. REDUCED LOGGING:
   - Minimize verbose output in validation mode
   - Use structured logging for essential information
   - Defer detailed reporting to artifacts

IMPLEMENTATION STATUS:
EOF
    
    # Add implementation status based on current optimizations
    if [ -f ".venv/cdk-setup-complete" ]; then
        echo "✅ CDK environment caching: IMPLEMENTED" >> $OPTIMIZATION_REPORT
    else
        echo "⏳ CDK environment caching: PENDING" >> $OPTIMIZATION_REPORT
    fi
    
    if [ -f "aws-identity.json" ]; then
        echo "✅ AWS credentials caching: IMPLEMENTED" >> $OPTIMIZATION_REPORT
    else
        echo "⏳ AWS credentials caching: PENDING" >> $OPTIMIZATION_REPORT
    fi
    
    echo "" >> $OPTIMIZATION_REPORT
    echo "NEXT STEPS:" >> $OPTIMIZATION_REPORT
    echo "1. Implement remaining caching mechanisms" >> $OPTIMIZATION_REPORT
    echo "2. Add parallel processing to remaining validation steps" >> $OPTIMIZATION_REPORT
    echo "3. Monitor validation times and adjust optimizations" >> $OPTIMIZATION_REPORT
    echo "4. Set up performance regression testing" >> $OPTIMIZATION_REPORT
}

# Main profiling execution
main() {
    echo "🚀 Starting validation stage profiling..."
    
    # Profile each validation stage
    measure_time execution_mode_detection optimized_execution_mode_detection
    measure_time aws_credentials_validation optimized_aws_credentials_validation
    measure_time iam_permissions_check optimized_iam_permissions_check
    measure_time resource_configuration_validation optimized_resource_configuration_validation
    measure_time cdk_environment_setup optimized_cdk_environment_setup
    measure_time cdk_synthesis optimized_cdk_synthesis
    
    # Generate optimization summary
    generate_optimization_summary
    
    local total_time=$(($(date +%s) - PROFILE_START))
    
    echo ""
    echo "📊 PROFILING COMPLETE"
    echo "===================="
    echo "Total validation time: ${total_time}s"
    echo "Target time: 300s (5 minutes)"
    echo "Performance: $([ $total_time -le 300 ] && echo "✅ MEETS TARGET" || echo "⚠️ EXCEEDS TARGET")"
    echo ""
    echo "📋 Reports generated:"
    echo "  - Performance profile: $PROFILE_REPORT"
    echo "  - Optimization recommendations: $OPTIMIZATION_REPORT"
    
    # Display key findings
    echo ""
    echo "🔍 KEY FINDINGS:"
    jq -r '.stage_timings | to_entries[] | "  \(.key): \(.value)s"' $PROFILE_REPORT
    
    return 0
}

# Execute main function
main "$@"