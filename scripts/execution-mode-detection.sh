#!/bin/bash

# Execution Mode Detection Script
# This script determines whether the workflow should run in validation or deployment mode
# based on the trigger type and branch information

set -e

echo "🔍 Execution Mode Detection"
echo "=========================="

# Initialize variables
EXECUTION_MODE=""
TRIGGER_TYPE="${CODECATALYST_TRIGGER_TYPE:-UNKNOWN}"
BRANCH_NAME="${CODECATALYST_SOURCE_BRANCH_NAME:-unknown}"
IS_MAIN_BRANCH="false"
SKIP_DEPLOYMENT="false"
SKIP_TESTING="false"

# Log environment information
echo "📊 Environment Information:"
echo "  Trigger Type: $TRIGGER_TYPE"
echo "  Branch Name: $BRANCH_NAME"
echo "  Commit Ref: ${CODECATALYST_SOURCE_BRANCH_REF:-unknown}"
echo "  Workflow Name: ${CODECATALYST_WORKFLOW_NAME:-unknown}"

# Determine if this is the main branch
if [ "$BRANCH_NAME" = "main" ]; then
    IS_MAIN_BRANCH="true"
    echo "✅ Running on main branch"
else
    IS_MAIN_BRANCH="false"
    echo "ℹ️ Running on branch: $BRANCH_NAME"
fi

# Determine execution mode based on trigger type and branch
echo ""
echo "🎯 Execution Mode Determination:"

case "$TRIGGER_TYPE" in
    "PULLREQUEST")
        EXECUTION_MODE="validation"
        SKIP_DEPLOYMENT="true"
        SKIP_TESTING="true"
        echo "  📋 Pull Request trigger detected"
        echo "  🔍 Mode: VALIDATION (validation stages only)"
        echo "  ⏭️ Deployment stages will be skipped"
        echo "  ⏭️ Testing stages will be skipped"
        ;;
    "PUSH")
        if [ "$IS_MAIN_BRANCH" = "true" ]; then
            EXECUTION_MODE="deployment"
            SKIP_DEPLOYMENT="false"
            SKIP_TESTING="false"
            echo "  🚀 Push to main branch detected"
            echo "  🏗️ Mode: DEPLOYMENT (all stages)"
            echo "  ✅ Deployment stages will execute"
            echo "  ✅ Testing stages will execute"
        else
            EXECUTION_MODE="validation"
            SKIP_DEPLOYMENT="true"
            SKIP_TESTING="true"
            echo "  🔀 Push to feature branch detected"
            echo "  🔍 Mode: VALIDATION (validation stages only)"
            echo "  ⏭️ Deployment stages will be skipped"
            echo "  ⏭️ Testing stages will be skipped"
        fi
        ;;
    "MANUAL")
        if [ "$IS_MAIN_BRANCH" = "true" ]; then
            EXECUTION_MODE="deployment"
            SKIP_DEPLOYMENT="false"
            SKIP_TESTING="false"
            echo "  👤 Manual trigger on main branch detected"
            echo "  🏗️ Mode: DEPLOYMENT (all stages)"
            echo "  ✅ Deployment stages will execute"
            echo "  ✅ Testing stages will execute"
        else
            EXECUTION_MODE="validation"
            SKIP_DEPLOYMENT="true"
            SKIP_TESTING="true"
            echo "  👤 Manual trigger on feature branch detected"
            echo "  🔍 Mode: VALIDATION (validation stages only)"
            echo "  ⏭️ Deployment stages will be skipped"
            echo "  ⏭️ Testing stages will be skipped"
        fi
        ;;
    *)
        # Fallback to validation mode for unknown trigger types
        EXECUTION_MODE="validation"
        SKIP_DEPLOYMENT="true"
        SKIP_TESTING="true"
        echo "  ⚠️ Unknown trigger type: $TRIGGER_TYPE"
        echo "  🔍 Mode: VALIDATION (fallback - validation stages only)"
        echo "  ⏭️ Deployment stages will be skipped"
        echo "  ⏭️ Testing stages will be skipped"
        ;;
esac

# Create execution context file
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo ""
echo "📝 Creating execution context..."

cat > execution-context.json << EOF
{
  "execution_mode": "$EXECUTION_MODE",
  "trigger_type": "$TRIGGER_TYPE",
  "branch_name": "$BRANCH_NAME",
  "is_main_branch": $IS_MAIN_BRANCH,
  "skip_deployment": $SKIP_DEPLOYMENT,
  "skip_testing": $SKIP_TESTING,
  "timestamp": "$TIMESTAMP",
  "commit_ref": "${CODECATALYST_SOURCE_BRANCH_REF:-unknown}",
  "workflow_name": "${CODECATALYST_WORKFLOW_NAME:-unknown}"
}
EOF

# Display execution context
echo "📋 Execution Context:"
cat execution-context.json | jq '.' 2>/dev/null || cat execution-context.json

# Export environment variables for use in subsequent steps
echo ""
echo "🔧 Exporting environment variables..."
echo "export EXECUTION_MODE=\"$EXECUTION_MODE\"" > execution-mode-env.sh
echo "export TRIGGER_TYPE=\"$TRIGGER_TYPE\"" >> execution-mode-env.sh
echo "export BRANCH_NAME=\"$BRANCH_NAME\"" >> execution-mode-env.sh
echo "export IS_MAIN_BRANCH=\"$IS_MAIN_BRANCH\"" >> execution-mode-env.sh
echo "export SKIP_DEPLOYMENT=\"$SKIP_DEPLOYMENT\"" >> execution-mode-env.sh
echo "export SKIP_TESTING=\"$SKIP_TESTING\"" >> execution-mode-env.sh

# Create summary for logging
echo ""
echo "📊 Execution Mode Summary:"
echo "========================="
echo "🎯 Mode: $EXECUTION_MODE"
echo "🔄 Trigger: $TRIGGER_TYPE"
echo "🌿 Branch: $BRANCH_NAME"
echo "🏗️ Deploy: $([ "$SKIP_DEPLOYMENT" = "false" ] && echo "YES" || echo "NO")"
echo "🧪 Test: $([ "$SKIP_TESTING" = "false" ] && echo "YES" || echo "NO")"

echo ""
echo "✅ Execution mode detection completed successfully"