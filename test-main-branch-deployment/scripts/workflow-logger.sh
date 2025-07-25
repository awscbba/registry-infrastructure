#!/bin/bash

# Workflow Logger Utility
# Provides consistent logging functions for the PR validation workflow
# Usage: source workflow-logger.sh

# Color codes for enhanced logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_stage_start() {
    local stage_name="$1"
    local execution_type="$2"  # "Always Executes" or "Conditional Execution"
    
    echo "📅 Stage Start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "🏷️ Stage: $stage_name ($execution_type)"
    echo ""
}

log_execution_context() {
    local execution_mode="$1"
    local trigger_type="$2"
    local branch_name="$3"
    local skip_deployment="$4"
    local skip_testing="$5"
    local stage_purpose="$6"
    
    echo "📊 Stage Execution Context:"
    echo "  Execution Mode: $execution_mode"
    echo "  Trigger Type: $trigger_type"
    echo "  Branch: $branch_name"
    echo "  Skip Deployment: $skip_deployment"
    echo "  Skip Testing: $skip_testing"
    echo "  Stage Purpose: $stage_purpose"
    echo ""
}

log_stage_decision() {
    local decision="$1"  # "EXECUTE" or "SKIP"
    local mode="$2"
    local reason="$3"
    local action="$4"
    local impact="$5"
    
    echo "🎯 Stage Decision Logic:"
    if [ "$decision" = "EXECUTE" ]; then
        echo "  ✅ Stage will be EXECUTED ($mode mode)"
    else
        echo "  ⏭️ Stage will be SKIPPED ($mode mode)"
    fi
    echo "  📝 Reason: $reason"
    echo "  🔧 Action: $action"
    if [ -n "$impact" ]; then
        echo "  🎯 Impact: $impact"
    fi
    echo ""
}

log_validation_mode_summary() {
    local stage_name="$1"
    local status="$2"  # "SKIPPED" or "COMPLETED"
    local execution_mode="$3"
    local next_stage="$4"
    local additional_info="$5"
    
    echo "📊 Stage Completion Summary (Validation Mode):"
    echo "  Stage: $stage_name"
    echo "  Status: $status"
    echo "  Execution Mode: $execution_mode"
    if [ -n "$additional_info" ]; then
        echo "  $additional_info"
    fi
    echo "  Next Stage: $next_stage"
    echo "  Duration: $(date -u +%Y-%m-%dT%H:%M:%SZ) (end time)"
    echo ""
}

log_deployment_mode_summary() {
    local stage_name="$1"
    local status="$2"  # "COMPLETED" or "FAILED"
    local execution_mode="$3"
    local next_stage="$4"
    local additional_info="$5"
    
    echo "📊 Stage Completion Summary (Deployment Mode):"
    echo "  Stage: $stage_name"
    echo "  Status: $status"
    echo "  Execution Mode: $execution_mode"
    if [ -n "$additional_info" ]; then
        echo "  $additional_info"
    fi
    echo "  Next Stage: $next_stage"
    echo "  Duration: $(date -u +%Y-%m-%dT%H:%M:%SZ) (end time)"
    echo ""
}

log_workflow_completion() {
    local execution_mode="$1"
    local trigger_type="$2"
    local branch_name="$3"
    
    echo "🎯 WORKFLOW COMPLETION SUMMARY:"
    echo "==============================="
    echo "  Execution Mode: $execution_mode"
    echo "  Trigger Type: $trigger_type"
    echo "  Branch: $branch_name"
    
    if [ "$execution_mode" = "validation" ]; then
        echo "  Stages Executed: CheckAPISync, PrepareAPIIntegration, ValidateInfrastructure, NotifyDeploymentStatus"
        echo "  Stages Skipped: DeployInfrastructure (placeholder), PostDeploymentTests (placeholder)"
        echo "  Infrastructure Changes: None (validation mode)"
        echo "  Outcome: Pull request validation feedback provided"
        echo ""
        echo "🔍 Pull request validation workflow completed - ready for code review"
    else
        echo "  Stages Executed: All stages"
        echo "  Stages Skipped: None"
        echo "  Infrastructure Changes: Applied to live environment"
        echo "  Outcome: Live application deployed and tested"
        echo ""
        echo "🚀 Full deployment workflow completed - application is live"
    fi
}

log_validation_only_message() {
    local trigger_type="$1"
    local branch_name="$2"
    
    echo "🔍 VALIDATION-ONLY EXECUTION"
    echo "============================"
    echo "This workflow is running in validation mode, which means:"
    echo ""
    echo "✅ What WILL happen:"
    echo "  • API code synchronization check"
    echo "  • API integration preparation"
    echo "  • Infrastructure configuration validation"
    echo "  • CDK synthesis validation"
    echo "  • IAM permission checks"
    echo "  • Resource configuration validation"
    echo "  • Status notification with validation results"
    echo ""
    echo "⏭️ What will be SKIPPED:"
    echo "  • Actual infrastructure deployment to AWS"
    echo "  • Post-deployment testing against live environment"
    echo "  • Live resource creation or modification"
    echo ""
    echo "🎯 Purpose:"
    if [ "$trigger_type" = "PULLREQUEST" ]; then
        echo "  • Validate pull request changes before merge"
        echo "  • Provide fast feedback to developers"
        echo "  • Catch configuration issues early"
        echo "  • Ensure code quality without infrastructure impact"
    else
        echo "  • Validate feature branch changes"
        echo "  • Test configuration without deploying"
        echo "  • Safe validation of infrastructure changes"
    fi
    echo ""
    echo "⚡ Expected duration: ~5-10 minutes (fast feedback)"
    echo "🔄 Trigger: $trigger_type on branch '$branch_name'"
    echo ""
}

log_deployment_mode_message() {
    local trigger_type="$1"
    local branch_name="$2"
    
    echo "🚀 FULL DEPLOYMENT EXECUTION"
    echo "============================"
    echo "This workflow is running in deployment mode, which means:"
    echo ""
    echo "✅ What WILL happen:"
    echo "  • Complete infrastructure validation"
    echo "  • CDK deployment to live AWS environment"
    echo "  • Resource creation and configuration"
    echo "  • Post-deployment testing against live APIs"
    echo "  • Comprehensive status notification"
    echo ""
    echo "🎯 Purpose:"
    echo "  • Deploy infrastructure changes to production"
    echo "  • Update live application environment"
    echo "  • Validate deployment with real traffic"
    echo "  • Ensure system health after changes"
    echo ""
    echo "⏱️ Expected duration: ~15-30 minutes (full deployment cycle)"
    echo "🔄 Trigger: $trigger_type on branch '$branch_name'"
    echo "🏗️ Impact: Live infrastructure will be modified"
    echo ""
}

# Export functions for use in other scripts
export -f log_stage_start
export -f log_execution_context
export -f log_stage_decision
export -f log_validation_mode_summary
export -f log_deployment_mode_summary
export -f log_workflow_completion
export -f log_validation_only_message
export -f log_deployment_mode_message