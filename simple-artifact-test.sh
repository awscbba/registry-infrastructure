#!/bin/bash

# Simple test to verify artifact handling works
set -e

echo "🧪 Simple Artifact Handling Test"
echo "================================"

# Test directory
TEST_DIR="/tmp/simple-artifact-test"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# Make artifact handler executable
ARTIFACT_HANDLER="/Users/sergio.rodriguez/Projects/Community/AWS/UserGroupCbba/CodeCatalyst/people-registry-03/registry-infrastructure/scripts/artifact-handler.sh"
chmod +x "$ARTIFACT_HANDLER"

echo "1. Testing placeholder creation..."
if "$ARTIFACT_HANDLER" create-placeholder deploymentSummary validation PULLREQUEST feature-branch "."; then
    echo "✅ Placeholder creation: PASS"
else
    echo "❌ Placeholder creation: FAIL"
    exit 1
fi

echo "2. Testing structure validation..."
if "$ARTIFACT_HANDLER" validate deploymentSummary "."; then
    echo "✅ Structure validation: PASS"
else
    echo "❌ Structure validation: FAIL"
    exit 1
fi

echo "3. Testing placeholder detection..."
if "$ARTIFACT_HANDLER" is-placeholder "deployment-summary.json"; then
    echo "✅ Placeholder detection: PASS"
else
    echo "❌ Placeholder detection: FAIL"
    exit 1
fi

echo "4. Testing data extraction..."
API_URL=$("$ARTIFACT_HANDLER" handle-data "deployment-summary.json" ".outputs.api_url" "fallback" 2>/dev/null)
if [[ "$API_URL" == "https://validation-placeholder.example.com/api" ]]; then
    echo "✅ Data extraction: PASS"
else
    echo "❌ Data extraction: FAIL (got: $API_URL)"
    exit 1
fi

echo "5. Testing consumption..."
if "$ARTIFACT_HANDLER" test-consumption deploymentSummary "."; then
    echo "✅ Consumption test: PASS"
else
    echo "❌ Consumption test: FAIL"
    exit 1
fi

echo ""
echo "🎉 All tests passed! Artifact handling system is working correctly."
echo ""
echo "Generated artifacts:"
ls -la

# Cleanup
cd /
rm -rf "$TEST_DIR"