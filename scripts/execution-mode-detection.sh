#!/bin/bash

# Execution Mode Detection Script
# This script determines whether the workflow should run in validation or deployment mode
# based on the trigger type and branch information

set -e

echo "🔍 Execution Mode Detection"
echo "=========================="
echo "📅 Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "🔧 Script Version: v1.2 (Enhanced Logging)"
echo ""

# Initialize variables
EXECUTION_MODE=""
TRIGGER_TYPE="${CODECATALYST_TRIGGER_TYPE:-UNKNOWN}"
BRANCH_NAME="${CODECATALYST_SOURCE_BRANCH_NAME:-unknown}"
IS_MAIN_BRANCH="false"
SKIP_DEPLOYMENT="false"
SKIP_TESTING="false"

# Log comprehensive environment information
echo "📊 Environment Information:"
echo "  Trigger Type: $TRIGGER_TYPE"
echo "  Branch Name: $BRANCH_NAME"
echo "  Commit Ref: ${CODECATALYST_SOURCE_BRANCH_REF:-unknown}"
echo "  Workflow Name: ${CODECATALYST_WORKFLOW_NAME:-unknown}"
echo "  Workflow Run ID: ${CODECATALYST_WORKFLOW_RUN_ID:-unknown}"
echo "  Project Name: ${CODECATALYST_PROJECT_NAME:-unknown}"
echo "  Space Name: ${CODECATALYST_SPACE_NAME:-unknown}"
echo ""

# Log trigger-specific information
echo "🎯 Trigger Analysis:"
case "$TRIGGER_TYPE" in
    "PULLREQUEST")
        echo "  📋 Pull Request Details:"
        echo "    - Event: ${CODECATALYST_PULLREQUEST_EVENT:-unknown}"
        echo "    - PR ID: ${CODECATALYST_PULLREQUEST_ID:-unknown}"
        echo "    - Source Branch: ${CODECATALYST_SOURCE_BRANCH_NAME:-unknown}"
        echo "    - Target Branch: ${CODECATALYST_TARGET_BRANCH_NAME:-unknown}"
        echo "    - Author: ${CODECATALYST_PULLREQUEST_AUTHOR:-unknown}"
        ;;
    "PUSH")
        echo "  🚀 Push Details:"
        echo "    - Branch: ${CODECATALYST_SOURCE_BRANCH_NAME:-unknown}"
        echo "    - Commit: ${CODECATALYST_SOURCE_BRANCH_REF:-unknown}"
        echo "    - Author: ${CODECATALYST_COMMIT_AUTHOR:-unknown}"
        ;;
    "MANUAL")
        echo "  👤 Manual Trigger Details:"
        echo "    - Branch: ${CODECATALYST_SOURCE_BRANCH_NAME:-unknown}"
        echo "    - Triggered By: ${CODECATALYST_ACTOR_NAME:-unknown}"
        ;;
    *)
        echo "  ⚠️ Unknown Trigger Type: $TRIGGER_TYPE"
        ;;
esac

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
        echo "  📝 Rationale: Pull requests run validation to catch issues before merge"
        echo "  ⏭️ Deployment stages will be skipped (no infrastructure changes)"
        echo "  ⏭️ Testing stages will be skipped (no live environment to test)"
        echo "  🎯 Expected stages: CheckAPISync → PrepareAPIIntegration → ValidateInfrastructure"
        echo "  ⚡ Fast feedback: ~5-10 minutes for validation results"
        ;;
    "PUSH")
        if [ "$IS_MAIN_BRANCH" = "true" ]; then
            EXECUTION_MODE="deployment"
            SKIP_DEPLOYMENT="false"
            SKIP_TESTING="false"
            echo "  🚀 Push to main branch detected"
            echo "  🏗️ Mode: DEPLOYMENT (all stages)"
            echo "  📝 Rationale: Main branch pushes deploy to live infrastructure"
            echo "  ✅ Deployment stages will execute (infrastructure changes applied)"
            echo "  ✅ Testing stages will execute (post-deployment validation)"
            echo "  🎯 Expected stages: All stages including DeployInfrastructure → PostDeploymentTests → NotifyDeploymentStatus"
            echo "  ⏱️ Full deployment: ~15-30 minutes for complete cycle"
        else
            EXECUTION_MODE="validation"
            SKIP_DEPLOYMENT="true"
            SKIP_TESTING="true"
            echo "  🔀 Push to feature branch detected"
            echo "  🔍 Mode: VALIDATION (validation stages only)"
            echo "  📝 Rationale: Feature branch pushes validate without deploying"
            echo "  ⏭️ Deployment stages will be skipped (no infrastructure changes)"
            echo "  ⏭️ Testing stages will be skipped (no live environment to test)"
            echo "  🎯 Expected stages: CheckAPISync → PrepareAPIIntegration → ValidateInfrastructure"
            echo "  ⚡ Fast feedback: ~5-10 minutes for validation results"
        fi
        ;;
    "MANUAL")
        if [ "$IS_MAIN_BRANCH" = "true" ]; then
            EXECUTION_MODE="deployment"
            SKIP_DEPLOYMENT="false"
            SKIP_TESTING="false"
            echo "  👤 Manual trigger on main branch detected"
            echo "  🏗️ Mode: DEPLOYMENT (all stages)"
            echo "  📝 Rationale: Manual deployment to main branch for infrastructure updates"
            echo "  ✅ Deployment stages will execute (infrastructure changes applied)"
            echo "  ✅ Testing stages will execute (post-deployment validation)"
            echo "  🎯 Expected stages: All stages including DeployInfrastructure → PostDeploymentTests → NotifyDeploymentStatus"
            echo "  ⏱️ Full deployment: ~15-30 minutes for complete cycle"
        else
            EXECUTION_MODE="validation"
            SKIP_DEPLOYMENT="true"
            SKIP_TESTING="true"
            echo "  👤 Manual trigger on feature branch detected"
            echo "  🔍 Mode: VALIDATION (validation stages only)"
            echo "  📝 Rationale: Manual validation on feature branch for testing changes"
            echo "  ⏭️ Deployment stages will be skipped (no infrastructure changes)"
            echo "  ⏭️ Testing stages will be skipped (no live environment to test)"
            echo "  🎯 Expected stages: CheckAPISync → PrepareAPIIntegration → ValidateInfrastructure"
            echo "  ⚡ Fast feedback: ~5-10 minutes for validation results"
        fi
        ;;
    *)
        # Fallback to validation mode for unknown trigger types
        EXECUTION_MODE="validation"
        SKIP_DEPLOYMENT="true"
        SKIP_TESTING="true"
        echo "  ⚠️ Unknown trigger type: $TRIGGER_TYPE"
        echo "  🔍 Mode: VALIDATION (fallback - validation stages only)"
        echo "  📝 Rationale: Unknown triggers default to safe validation mode"
        echo "  ⏭️ Deployment stages will be skipped (safety measure)"
        echo "  ⏭️ Testing stages will be skipped (no deployment to test)"
        echo "  🎯 Expected stages: CheckAPISync → PrepareAPIIntegration → ValidateInfrastructure"
        echo "  ⚡ Fast feedback: ~5-10 minutes for validation results"
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

# Create comprehensive summary for logging
echo ""
echo "📊 Execution Mode Summary:"
echo "========================="
echo "🎯 Mode: $EXECUTION_MODE"
echo "🔄 Trigger: $TRIGGER_TYPE"
echo "🌿 Branch: $BRANCH_NAME"
echo "🏗️ Deploy: $([ "$SKIP_DEPLOYMENT" = "false" ] && echo "YES" || echo "NO")"
echo "🧪 Test: $([ "$SKIP_TESTING" = "false" ] && echo "YES" || echo "NO")"
echo ""

# Log stage execution plan
echo "📋 Stage Execution Plan:"
echo "========================"
echo "✅ CheckAPISync - WILL EXECUTE (always runs)"
echo "✅ PrepareAPIIntegration - WILL EXECUTE (always runs)"  
echo "✅ ValidateInfrastructure - WILL EXECUTE (always runs)"

if [ "$SKIP_DEPLOYMENT" = "false" ]; then
    echo "✅ DeployInfrastructure - WILL EXECUTE ($EXECUTION_MODE mode)"
else
    echo "⏭️ DeployInfrastructure - WILL SKIP ($EXECUTION_MODE mode - creates placeholder artifacts)"
fi

if [ "$SKIP_TESTING" = "false" ]; then
    echo "✅ PostDeploymentTests - WILL EXECUTE ($EXECUTION_MODE mode)"
else
    echo "⏭️ PostDeploymentTests - WILL SKIP ($EXECUTION_MODE mode - creates placeholder artifacts)"
fi

echo "✅ NotifyDeploymentStatus - WILL EXECUTE (always runs - mode-specific notifications)"

echo ""
if [ "$EXECUTION_MODE" = "validation" ]; then
    echo "🔍 VALIDATION MODE SUMMARY:"
    echo "  • Purpose: Validate configuration and catch issues before merge"
    echo "  • Duration: ~5-10 minutes (fast feedback)"
    echo "  • Infrastructure: No changes made to live environment"
    echo "  • Artifacts: Placeholder artifacts created for downstream compatibility"
    echo "  • Outcome: Pull request status check (green/red)"
else
    echo "🚀 DEPLOYMENT MODE SUMMARY:"
    echo "  • Purpose: Deploy infrastructure changes to live environment"
    echo "  • Duration: ~15-30 minutes (full deployment cycle)"
    echo "  • Infrastructure: Live AWS resources created/updated"
    echo "  • Artifacts: Real deployment artifacts with live URLs and resources"
    echo "  • Outcome: Live application deployment with post-deployment testing"
fi

echo ""
echo "✅ Execution mode detection completed successfully"
echo "📝 Next: Workflow stages will use these settings for conditional execution"