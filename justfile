# People Register Infrastructure - Justfile
# This file contains automation tasks for the People Register project

# Default recipe to show available commands
default:
    @just --list

# Colors for output
RED := '\033[0;31m'
GREEN := '\033[0;32m'
YELLOW := '\033[1;33m'
BLUE := '\033[0;34m'
NC := '\033[0m'

# Variables
STACK_NAME := "PeopleRegisterInfrastructureStack"
FRONTEND_DIR := "../people-register-frontend"
API_DIR := "../people-register-api"
WORK_DIR := "/tmp/people-register-deployment"

# CodeCatalyst repository URLs (update these with your actual URLs)
CODECATALYST_BASE_URL := "https://srinclan@git.us-west-2.codecatalyst.aws/v1/AWSCocha/people-registry"
INFRASTRUCTURE_REPO := CODECATALYST_BASE_URL + "/registry-infrastructure"
API_REPO := CODECATALYST_BASE_URL + "/registry-api"
FRONTEND_REPO := CODECATALYST_BASE_URL + "/register-frontend"

# Print colored status messages
print-info message:
    @echo -e "{{BLUE}}[INFO]{{NC}} {{message}}"

print-success message:
    @echo -e "{{GREEN}}[SUCCESS]{{NC}} {{message}}"

print-warning message:
    @echo -e "{{YELLOW}}[WARNING]{{NC}} {{message}}"

print-error message:
    @echo -e "{{RED}}[ERROR]{{NC}} {{message}}"

# Legacy aliases for backward compatibility
print-status message:
    @just print-info "{{message}}"

# Check if required tools are installed (comprehensive version)
check-prerequisites:
    @just print-info "Checking prerequisites..."
    @command -v aws >/dev/null 2>&1 || (just print-error "AWS CLI is not installed or not in PATH" && exit 1)
    @aws sts get-caller-identity >/dev/null 2>&1 || (just print-error "AWS credentials not configured or expired. Please run 'aws configure' or 'aws sso login'" && exit 1)
    @command -v node >/dev/null 2>&1 || (just print-error "Node.js is not installed. Please install Node.js 18+ first." && exit 1)
    @command -v python3 >/dev/null 2>&1 || (just print-error "Python 3 is not installed. Please install Python 3.11+ first." && exit 1)
    @command -v git >/dev/null 2>&1 || (just print-error "Git is not installed. Please install Git first." && exit 1)
    @if ! command -v cdk >/dev/null 2>&1; then \
        just print-warning "AWS CDK is not installed. Installing now..."; \
        npm install -g aws-cdk; \
    fi
    @if ! command -v jq >/dev/null 2>&1; then \
        just print-warning "jq is not installed. Installing now..."; \
        if command -v brew >/dev/null 2>&1; then \
            brew install jq; \
        elif command -v apt-get >/dev/null 2>&1; then \
            sudo apt-get update && sudo apt-get install -y jq; \
        else \
            just print-error "Please install jq manually"; \
            exit 1; \
        fi; \
    fi
    @just print-success "All prerequisites are met!"

# Legacy alias for backward compatibility
check-requirements: check-prerequisites

# Setup workspace for multi-repo deployment
setup-workspace:
    @just print-info "Setting up workspace..."
    @if [ -d "{{WORK_DIR}}" ]; then rm -rf "{{WORK_DIR}}"; fi
    @mkdir -p "{{WORK_DIR}}"
    @just print-success "Workspace created at {{WORK_DIR}}"

# Clone repositories for deployment
clone-repos:
    @just print-info "Cloning repositories..."
    @cd "{{WORK_DIR}}" && git clone "{{INFRASTRUCTURE_REPO}}" infrastructure
    @cd "{{WORK_DIR}}" && git clone "{{API_REPO}}" api
    @cd "{{WORK_DIR}}" && git clone "{{FRONTEND_REPO}}" frontend
    @just print-success "All repositories cloned"

# Deploy infrastructure with comprehensive output handling
deploy-infrastructure-full:
    @just print-info "Deploying infrastructure..."
    @if [ ! -d ".venv" ]; then \
        just print-info "Setting up Python virtual environment..."; \
        python3 -m venv .venv; \
    fi
    @source .venv/bin/activate && pip install -r requirements.txt
    @just print-info "Checking CDK bootstrap status..."
    @if ! aws cloudformation describe-stacks --stack-name CDKToolkit >/dev/null 2>&1; then \
        just print-info "Bootstrapping CDK..."; \
        source .venv/bin/activate && cdk bootstrap; \
    else \
        just print-info "CDK already bootstrapped"; \
    fi
    @just print-info "Deploying CDK stack..."
    @source .venv/bin/activate && cdk deploy --require-approval never --outputs-file outputs.json
    @if [ -f "outputs.json" ]; then \
        just print-success "Infrastructure deployed successfully!"; \
        just extract-outputs; \
    else \
        just print-error "Failed to get deployment outputs"; \
        exit 1; \
    fi

# Extract and display deployment outputs
extract-outputs:
    @just print-info "Extracting deployment outputs..."
    @API_URL=$$(cat outputs.json | jq -r '.{{STACK_NAME}}.ApiUrl // empty'); \
    FRONTEND_URL=$$(cat outputs.json | jq -r '.{{STACK_NAME}}.FrontendUrl // empty'); \
    S3_BUCKET=$$(cat outputs.json | jq -r '.{{STACK_NAME}}.S3BucketName // empty'); \
    DYNAMODB_TABLE=$$(cat outputs.json | jq -r '.{{STACK_NAME}}.DynamoDBTableName // empty'); \
    DISTRIBUTION_ID=$$(aws cloudfront list-distributions --query "DistributionList.Items[?Comment==''].Id" --output text 2>/dev/null || echo ""); \
    just print-info "API URL: $$API_URL"; \
    just print-info "Frontend URL: $$FRONTEND_URL"; \
    just print-info "S3 Bucket: $$S3_BUCKET"; \
    just print-info "DynamoDB Table: $$DYNAMODB_TABLE"; \
    just print-info "CloudFront Distribution ID: $$DISTRIBUTION_ID"; \
    echo "API_URL=$$API_URL" > deployment-outputs.env; \
    echo "FRONTEND_URL=$$FRONTEND_URL" >> deployment-outputs.env; \
    echo "S3_BUCKET=$$S3_BUCKET" >> deployment-outputs.env; \
    echo "DYNAMODB_TABLE=$$DYNAMODB_TABLE" >> deployment-outputs.env; \
    echo "DISTRIBUTION_ID=$$DISTRIBUTION_ID" >> deployment-outputs.env

# Test API endpoints
test-api:
    @just print-info "Testing API deployment..."
    @if [ ! -f "deployment-outputs.env" ]; then \
        just print-error "deployment-outputs.env not found. Run deploy-infrastructure-full first."; \
        exit 1; \
    fi
    @source deployment-outputs.env && \
    if curl -f -s "$$API_URL/health" >/dev/null; then \
        just print-success "API health check passed"; \
    else \
        just print-error "API health check failed"; \
        exit 1; \
    fi
    @source deployment-outputs.env && \
    if curl -f -s "$$API_URL/people" >/dev/null; then \
        just print-success "API people endpoint working"; \
    else \
        just print-error "API people endpoint failed"; \
        exit 1; \
    fi

# Deploy frontend with environment configuration
deploy-frontend-full:
    @just print-info "Deploying frontend..."
    @if [ ! -f "deployment-outputs.env" ]; then \
        just print-error "deployment-outputs.env not found. Run deploy-infrastructure-full first."; \
        exit 1; \
    fi
    @source deployment-outputs.env && \
    cd "{{FRONTEND_DIR}}" && \
    just print-info "Installing frontend dependencies..." && \
    npm install && \
    just print-info "Configuring frontend environment..." && \
    echo "PUBLIC_API_URL=$$API_URL" > .env && \
    just print-info "Building frontend..." && \
    npm run build && \
    just print-info "Deploying to S3..." && \
    aws s3 sync dist/ "s3://$$S3_BUCKET" --delete && \
    if [ -n "$$DISTRIBUTION_ID" ]; then \
        just print-info "Invalidating CloudFront cache..."; \
        aws cloudfront create-invalidation --distribution-id "$$DISTRIBUTION_ID" --paths "/*" >/dev/null; \
        just print-success "CloudFront cache invalidated"; \
    fi
    @just print-success "Frontend deployed successfully!"

# Test frontend deployment
test-frontend:
    @just print-info "Testing frontend deployment..."
    @if [ ! -f "deployment-outputs.env" ]; then \
        just print-error "deployment-outputs.env not found. Run deploy-infrastructure-full first."; \
        exit 1; \
    fi
    @just print-info "Waiting for CloudFront to update..."
    @sleep 10
    @source deployment-outputs.env && \
    if curl -f -s "$$FRONTEND_URL" >/dev/null; then \
        just print-success "Frontend is accessible"; \
    else \
        just print-warning "Frontend might still be propagating through CloudFront"; \
    fi

# Create test data
create-test-data:
    @just print-info "Creating test data..."
    @if [ ! -f "deployment-outputs.env" ]; then \
        just print-error "deployment-outputs.env not found. Run deploy-infrastructure-full first."; \
        exit 1; \
    fi
    @source deployment-outputs.env && \
    curl -X POST "$$API_URL/people" \
        -H "Content-Type: application/json" \
        -d '{"firstName": "John", "lastName": "Doe", "email": "john.doe@example.com", "phone": "+1-555-123-4567", "dateOfBirth": "1990-01-01", "address": {"street": "123 Main St", "city": "Anytown", "state": "CA", "zipCode": "12345", "country": "USA"}}' >/dev/null && \
    curl -X POST "$$API_URL/people" \
        -H "Content-Type: application/json" \
        -d '{"firstName": "Jane", "lastName": "Smith", "email": "jane.smith@example.com", "phone": "+1-555-987-6543", "dateOfBirth": "1985-05-15", "address": {"street": "456 Oak Ave", "city": "Springfield", "state": "NY", "zipCode": "67890", "country": "USA"}}' >/dev/null
    @just print-success "Test data created"

# Print comprehensive deployment summary
print-deployment-summary:
    @just print-success "🎉 Deployment completed successfully!"
    @echo ""
    @echo "📋 Deployment Summary:"
    @echo "======================"
    @if [ -f "deployment-outputs.env" ]; then \
        source deployment-outputs.env && \
        echo "🔧 API URL: $$API_URL" && \
        echo "🎨 Frontend URL: $$FRONTEND_URL" && \
        echo "🗄️  S3 Bucket: $$S3_BUCKET" && \
        echo "📊 DynamoDB Table: $$DYNAMODB_TABLE" && \
        echo "🌐 CloudFront Distribution: $$DISTRIBUTION_ID" && \
        echo "" && \
        echo "🧪 Test your application:" && \
        echo "- API Health: curl $$API_URL/health" && \
        echo "- List People: curl $$API_URL/people" && \
        echo "- Frontend: Open $$FRONTEND_URL in your browser" && \
        echo "" && \
        echo "💰 Estimated monthly cost: \$$6-8 USD for low traffic" && \
        echo "" && \
        echo "📚 Next steps:" && \
        echo "- Set up monitoring and alerts" && \
        echo "- Configure custom domain names" && \
        echo "- Set up CI/CD pipelines in CodeCatalyst" && \
        echo "- Add authentication if needed"; \
    else \
        just print-warning "deployment-outputs.env not found. Run deploy-infrastructure-full first."; \
    fi

# Complete deployment pipeline (replaces deploy-all.sh)
deploy-all-comprehensive: check-prerequisites deploy-infrastructure-full test-api deploy-frontend-full test-frontend create-test-data print-deployment-summary
    @just print-success "🚀 Complete People Register Application Deployment Finished!"

# Multi-repository deployment (clones repos first)
deploy-all-from-repos: check-prerequisites setup-workspace clone-repos
    @cd "{{WORK_DIR}}/infrastructure" && just deploy-infrastructure-full
    @cd "{{WORK_DIR}}/infrastructure" && just test-api
    @cd "{{WORK_DIR}}/infrastructure" && just deploy-frontend-full
    @cd "{{WORK_DIR}}/infrastructure" && just test-frontend
    @cd "{{WORK_DIR}}/infrastructure" && just create-test-data
    @cd "{{WORK_DIR}}/infrastructure" && just print-deployment-summary
    @just print-success "🚀 Multi-repository deployment completed!"

# Cleanup workspace
cleanup-workspace:
    @just print-info "Cleaning up workspace..."
    @if [ -d "{{WORK_DIR}}" ]; then rm -rf "{{WORK_DIR}}"; fi
    @just print-success "Cleanup completed"

# Interactive cleanup prompt
cleanup-interactive:
    @echo ""
    @echo "Do you want to clean up the temporary workspace at {{WORK_DIR}}? (y/N):"
    @read -r response && \
    if [ "$$response" = "y" ] || [ "$$response" = "Y" ]; then \
        just cleanup-workspace; \
    else \
        just print-info "Workspace preserved at: {{WORK_DIR}}"; \
    fi

# Helper to get S3 bucket name
get-bucket-name:
    @aws cloudformation describe-stacks \
        --stack-name {{STACK_NAME}} \
        --query 'Stacks[0].Outputs[?OutputKey==`S3BucketName`].OutputValue' \
        --output text 2>/dev/null || echo ""

# Helper to get CloudFront distribution ID
get-distribution-id:
    @aws cloudfront list-distributions \
        --query "DistributionList.Items[?Comment==''].Id" \
        --output text 2>/dev/null || echo ""

# Helper to get API URL
get-api-url:
    @aws cloudformation describe-stacks \
        --stack-name {{STACK_NAME}} \
        --query 'Stacks[0].Outputs[?OutputKey==`ApiUrl`].OutputValue' \
        --output text 2>/dev/null || echo ""

# Helper to get Frontend URL
get-frontend-url:
    @aws cloudformation describe-stacks \
        --stack-name {{STACK_NAME}} \
        --query 'Stacks[0].Outputs[?OutputKey==`FrontendUrl`].OutputValue' \
        --output text 2>/dev/null || echo ""

# Install frontend dependencies
install-frontend-deps:
    @just print-status "Checking frontend dependencies..."
    @if [ ! -d "{{FRONTEND_DIR}}/node_modules" ]; then \
        just print-status "Installing frontend dependencies..."; \
        cd {{FRONTEND_DIR}} && npm install; \
    else \
        just print-status "Frontend dependencies already installed"; \
    fi

# Build the frontend application
build-frontend:
    @just print-status "Building frontend..."
    @API_URL=$(just get-api-url); \
    cd {{FRONTEND_DIR}}; \
    if [ -n "$API_URL" ]; then \
        export PUBLIC_API_URL="$API_URL"; \
        echo "PUBLIC_API_URL=$API_URL" > .env; \
        just print-status "Set API URL: $API_URL"; \
    fi; \
    npm run build
    @if [ ! -d "{{FRONTEND_DIR}}/dist" ]; then \
        just print-error "Build failed - dist directory not found"; \
        exit 1; \
    fi
    @just print-status "Frontend build completed"

# Deploy frontend files to S3
deploy-to-s3:
    @just print-status "Deploying to S3..."
    @BUCKET_NAME=$(just get-bucket-name); \
    if [ -z "$BUCKET_NAME" ]; then \
        just print-error "Could not retrieve S3 bucket name from stack outputs"; \
        just print-warning "Make sure the infrastructure stack is deployed"; \
        exit 1; \
    fi; \
    just print-status "S3 Bucket: $BUCKET_NAME"; \
    aws s3 sync {{FRONTEND_DIR}}/dist/ "s3://$BUCKET_NAME" \
        --delete \
        --cache-control "public, max-age=31536000" \
        --exclude "*.html" \
        --exclude "*.json"; \
    aws s3 sync {{FRONTEND_DIR}}/dist/ "s3://$BUCKET_NAME" \
        --delete \
        --cache-control "public, max-age=0, must-revalidate" \
        --include "*.html" \
        --include "*.json"
    @just print-status "Files uploaded to S3"

# Invalidate CloudFront cache
invalidate-cloudfront:
    @DISTRIBUTION_ID=$(just get-distribution-id); \
    if [ -n "$DISTRIBUTION_ID" ]; then \
        just print-status "CloudFront Distribution ID: $DISTRIBUTION_ID"; \
        just print-status "Invalidating CloudFront cache..."; \
        INVALIDATION_ID=$(aws cloudfront create-invalidation \
            --distribution-id "$DISTRIBUTION_ID" \
            --paths "/*" \
            --query 'Invalidation.Id' \
            --output text); \
        just print-status "CloudFront invalidation created: $INVALIDATION_ID"; \
        just print-status "Cache invalidation may take 5-15 minutes to complete"; \
    else \
        just print-warning "Skipping CloudFront invalidation - distribution ID not found"; \
    fi

# Show current stack information
show-info:
    @just print-status "Stack Information:"
    @BUCKET_NAME=$(just get-bucket-name); \
    API_URL=$(just get-api-url); \
    FRONTEND_URL=$(just get-frontend-url); \
    DISTRIBUTION_ID=$(just get-distribution-id); \
    echo "Stack Name: {{STACK_NAME}}"; \
    echo "S3 Bucket: $BUCKET_NAME"; \
    echo "API URL: $API_URL"; \
    echo "Frontend URL: $FRONTEND_URL"; \
    echo "CloudFront Distribution ID: $DISTRIBUTION_ID"

# Deploy the complete frontend (full pipeline)
deploy-frontend: check-requirements install-frontend-deps build-frontend deploy-to-s3 invalidate-cloudfront
    @just print-status "Frontend deployment completed successfully!"
    @FRONTEND_URL=$(just get-frontend-url); \
    if [ -n "$FRONTEND_URL" ]; then \
        just print-status "Frontend URL: $FRONTEND_URL"; \
    fi

# Clean frontend build artifacts
clean-frontend:
    @just print-status "Cleaning frontend build artifacts..."
    @rm -rf {{FRONTEND_DIR}}/dist
    @rm -f {{FRONTEND_DIR}}/.env
    @just print-status "Frontend cleaned"

# Clean frontend dependencies
clean-frontend-deps:
    @just print-status "Cleaning frontend dependencies..."
    @rm -rf {{FRONTEND_DIR}}/node_modules
    @rm -f {{FRONTEND_DIR}}/package-lock.json
    @just print-status "Frontend dependencies cleaned"

# Full clean (build artifacts + dependencies)
clean-all: clean-frontend clean-frontend-deps
    @just print-status "All frontend artifacts cleaned"

# Development helpers
dev-frontend:
    @just print-status "Starting frontend development server..."
    @API_URL=$(just get-api-url); \
    cd {{FRONTEND_DIR}}; \
    if [ -n "$API_URL" ]; then \
        export PUBLIC_API_URL="$API_URL"; \
        echo "PUBLIC_API_URL=$API_URL" > .env; \
        just print-status "Set API URL for development: $API_URL"; \
    fi; \
    npm run dev

# CDK related tasks
cdk-bootstrap:
    @just print-status "Bootstrapping CDK..."
    @cdk bootstrap

cdk-deploy:
    @just print-status "Deploying CDK stack..."
    @cdk deploy

cdk-destroy:
    @just print-status "Destroying CDK stack..."
    @cdk destroy

cdk-diff:
    @just print-status "Showing CDK diff..."
    @cdk diff

cdk-synth:
    @just print-status "Synthesizing CDK stack..."
    @cdk synth

# Complete deployment pipeline (infrastructure + frontend)
deploy-all: cdk-deploy deploy-frontend
    @just print-status "Complete deployment finished!"
    @just show-info

# Quick frontend update (skip dependency installation)
quick-deploy-frontend: check-requirements build-frontend deploy-to-s3 invalidate-cloudfront
    @just print-status "Quick frontend deployment completed!"

# Validate deployment
validate-deployment:
    @just print-status "Validating deployment..."
    @FRONTEND_URL=$(just get-frontend-url); \
    API_URL=$(just get-api-url); \
    if [ -n "$FRONTEND_URL" ]; then \
        just print-status "Testing frontend URL: $FRONTEND_URL"; \
        curl -s -o /dev/null -w "%{http_code}" "$FRONTEND_URL" | grep -q "200" && \
            just print-status "Frontend is accessible" || \
            just print-warning "Frontend may not be accessible"; \
    fi; \
    if [ -n "$API_URL" ]; then \
        just print-status "Testing API health endpoint: $API_URL/health"; \
        curl -s -o /dev/null -w "%{http_code}" "$API_URL/health" | grep -q "200" && \
            just print-status "API is accessible" || \
            just print-warning "API may not be accessible"; \
    fi

# Show logs for troubleshooting
show-logs:
    @just print-status "Recent CloudFormation events:"
    @aws cloudformation describe-stack-events \
        --stack-name {{STACK_NAME}} \
        --max-items 10 \
        --query 'StackEvents[*].[Timestamp,ResourceStatus,ResourceType,LogicalResourceId]' \
        --output table

# Help command with detailed descriptions
help:
    @echo "People Register Infrastructure - Available Commands:"
    @echo ""
    @echo "🚀 Complete Deployment Pipelines:"
    @echo "  deploy-all-comprehensive    - Complete deployment (infrastructure + frontend + testing)"
    @echo "  deploy-all-from-repos      - Multi-repo deployment (clones repos first)"
    @echo "  deploy-all                 - Deploy infrastructure and frontend (local repos)"
    @echo ""
    @echo "🏗️  Infrastructure Commands:"
    @echo "  deploy-infrastructure-full - Deploy infrastructure with comprehensive output handling"
    @echo "  cdk-bootstrap              - Bootstrap CDK"
    @echo "  cdk-deploy                 - Deploy CDK stack"
    @echo "  cdk-destroy                - Destroy CDK stack"
    @echo "  cdk-diff                   - Show CDK diff"
    @echo "  cdk-synth                  - Synthesize CDK stack"
    @echo ""
    @echo "🎨 Frontend Commands:"
    @echo "  deploy-frontend-full       - Deploy frontend with environment configuration"
    @echo "  deploy-frontend            - Deploy frontend only (standard pipeline)"
    @echo "  quick-deploy-frontend      - Quick frontend deployment (skip deps installation)"
    @echo "  build-frontend             - Build frontend application"
    @echo "  install-frontend-deps      - Install frontend dependencies"
    @echo ""
    @echo "🧪 Testing Commands:"
    @echo "  test-api                   - Test API endpoints"
    @echo "  test-frontend              - Test frontend deployment"
    @echo "  create-test-data           - Create sample data in the application"
    @echo "  validate-deployment        - Validate deployment status"
    @echo ""
    @echo "🔧 Development Commands:"
    @echo "  dev-frontend               - Start frontend development server"
    @echo "  check-prerequisites        - Check if required tools are installed"
    @echo "  extract-outputs            - Extract and display deployment outputs"
    @echo ""
    @echo "🗂️  Repository Management:"
    @echo "  setup-workspace            - Setup workspace for multi-repo deployment"
    @echo "  clone-repos                - Clone all repositories"
    @echo "  cleanup-workspace          - Clean up temporary workspace"
    @echo "  cleanup-interactive        - Interactive cleanup prompt"
    @echo ""
    @echo "🧹 Cleanup Commands:"
    @echo "  clean-frontend             - Clean frontend build artifacts"
    @echo "  clean-frontend-deps        - Clean frontend dependencies"
    @echo "  clean-all                  - Clean everything"
    @echo ""
    @echo "ℹ️  Information Commands:"
    @echo "  show-info                  - Show current stack information"
    @echo "  print-deployment-summary   - Print comprehensive deployment summary"
    @echo "  show-logs                  - Show recent CloudFormation events"
    @echo ""
    @echo "🔐 RBAC & Security Commands:"
    @echo "  rbac-full-setup <email>    - Complete RBAC setup with testing"
    @echo "  auth-full-diagnostics      - Complete authentication diagnostics"
    @echo "  security-full-audit        - Complete security audit"
    @echo "  help-scripts               - Show all script tasks (detailed)"
    @echo ""
    @echo "📖 Usage Examples:"
    @echo "  just deploy-all-comprehensive          # Complete deployment with testing"
    @echo "  just deploy-all-from-repos             # Multi-repository deployment"
    @echo "  just deploy-infrastructure-full        # Infrastructure only"
    @echo "  just deploy-frontend-full              # Frontend only (with env config)"
    @echo "  just test-api && just test-frontend    # Test deployments"
    @echo "  just create-test-data                  # Add sample data"
    @echo "  just print-deployment-summary          # Show deployment info"
    @echo "  just rbac-full-setup admin@example.com # Setup RBAC system"
    @echo "  just auth-full-diagnostics             # Diagnose auth issues"
    @echo ""
    @echo "🔄 Migration from deploy-all.sh:"
    @echo "  ./deploy-all.sh  →  just deploy-all-comprehensive"

# ============================================================================
# RBAC (Role-Based Access Control) Management
# ============================================================================

# Create DynamoDB roles table for RBAC system
rbac-create-table:
    @just print-info "Creating DynamoDB roles table for RBAC system..."
    @python3 scripts/create_roles_table.py
    @just print-success "RBAC table creation completed"

# Show RBAC implementation summary and migration guide
rbac-show-summary:
    @just print-info "Displaying RBAC implementation summary..."
    @python3 scripts/role_based_access_control_summary.py

# Create admin user in the system
rbac-create-admin email:
    @just print-info "Creating admin user: {{email}}"
    @python3 scripts/create_admin_user.py --email "{{email}}"
    @just print-success "Admin user created successfully"

# Check admin user status
rbac-check-admin email:
    @just print-info "Checking admin user status: {{email}}"
    @python3 scripts/check_admin_user.py --email "{{email}}"

# Delete admin user
rbac-delete-admin email:
    @just print-warning "Deleting admin user: {{email}}"
    @python3 scripts/delete_admin_user.py --email "{{email}}"
    @just print-success "Admin user deleted"

# Complete RBAC setup (table + initial admin)
rbac-setup email:
    @just print-info "Setting up complete RBAC system..."
    @just rbac-create-table
    @just rbac-create-admin "{{email}}"
    @just print-success "RBAC system setup completed for {{email}}"

# ============================================================================
# Authentication & Security Diagnostics
# ============================================================================

# Run comprehensive authentication diagnostics
auth-diagnose:
    @just print-info "Running authentication diagnostics..."
    @python3 scripts/debug_live_auth_issue.py
    @just print-success "Authentication diagnostics completed"

# Monitor authentication logs in real-time
auth-monitor-logs:
    @just print-info "Starting authentication log monitoring..."
    @python3 scripts/monitor_auth_logs.py

# Monitor X-Ray authentication flow
auth-monitor-xray:
    @just print-info "Starting X-Ray authentication flow monitoring..."
    @python3 scripts/monitor_xray_auth_flow.py

# Test user login flow
auth-test-login email:
    @just print-info "Testing login flow for: {{email}}"
    @python3 scripts/test_user_login_flow.py --email "{{email}}"

# Test session persistence
auth-test-session:
    @just print-info "Testing session persistence..."
    @python3 scripts/test_session_persistence.py

# Diagnose frontend authentication issues
auth-diagnose-frontend:
    @just print-info "Diagnosing frontend authentication issues..."
    @python3 scripts/diagnose_frontend_auth_issue.py

# Create debug bookmarklet for browser debugging
auth-create-bookmarklet:
    @just print-info "Creating authentication debug bookmarklet..."
    @python3 scripts/create_debug_bookmarklet.py
    @just print-success "Debug bookmarklet created"

# Create log interceptor for debugging
auth-create-interceptor:
    @just print-info "Creating authentication log interceptor..."
    @python3 scripts/create_log_interceptor.py
    @just print-success "Log interceptor created"

# ============================================================================
# Production Diagnostics & Monitoring
# ============================================================================

# Diagnose production 502 errors
prod-diagnose-502:
    @just print-info "Diagnosing production 502 errors..."
    @python3 scripts/diagnose_production_502.py

# Run security vulnerability report
security-scan:
    @just print-info "Running security vulnerability scan..."
    @python3 scripts/security_vulnerability_report.py
    @just print-success "Security scan completed"

# Debug password hash issues
debug-password-hash:
    @just print-info "Debugging password hash issues..."
    @python3 scripts/debug_password_hash_issue.py

# Investigate authentication issues
investigate-auth:
    @just print-info "Investigating authentication issues..."
    @python3 scripts/investigate_auth_issue.py

# ============================================================================
# Summary & Documentation Scripts
# ============================================================================

# Show authentication improvements summary
show-auth-improvements:
    @just print-info "Displaying authentication improvements summary..."
    @python3 scripts/authentication_improvements_summary.py

# Show authentication issue summary
show-auth-issues:
    @just print-info "Displaying authentication issue summary..."
    @python3 scripts/auth_issue_summary.py

# Show login fix summary
show-login-fixes:
    @just print-info "Displaying login fix summary..."
    @python3 scripts/login_fix_summary.py

# Show test fixes summary
show-test-fixes:
    @just print-info "Displaying test fixes summary..."
    @python3 scripts/test_fixes_summary.py

# Show final test resolution summary
show-final-resolution:
    @just print-info "Displaying final test resolution summary..."
    @python3 scripts/final_test_resolution_summary.py

# ============================================================================
# Bash Script Wrappers
# ============================================================================

# Deploy frontend using bash script
deploy-frontend-bash:
    @just print-info "Deploying frontend using bash script..."
    @chmod +x scripts/deploy-frontend.sh
    @./scripts/deploy-frontend.sh
    @just print-success "Frontend deployment completed"

# Run performance profiler
run-performance-profiler:
    @just print-info "Running performance profiler..."
    @chmod +x scripts/performance-profiler.sh
    @./scripts/performance-profiler.sh

# Run optimized validation
run-optimized-validation:
    @just print-info "Running optimized validation..."
    @chmod +x scripts/optimized-validation.sh
    @./scripts/optimized-validation.sh

# Run workflow logger
run-workflow-logger:
    @just print-info "Starting workflow logger..."
    @chmod +x scripts/workflow-logger.sh
    @./scripts/workflow-logger.sh

# Run execution mode detection
detect-execution-mode:
    @just print-info "Detecting execution mode..."
    @chmod +x scripts/execution-mode-detection.sh
    @./scripts/execution-mode-detection.sh

# Handle artifacts
handle-artifacts:
    @just print-info "Handling artifacts..."
    @chmod +x scripts/artifact-handler.sh
    @./scripts/artifact-handler.sh

# Test artifact compatibility
test-artifact-compatibility:
    @just print-info "Testing artifact compatibility..."
    @chmod +x scripts/test-artifact-compatibility.sh
    @./scripts/test-artifact-compatibility.sh

# ============================================================================
# Comprehensive Task Groups
# ============================================================================

# Complete RBAC setup and testing
rbac-full-setup email:
    @just print-info "🚀 Starting complete RBAC setup..."
    @just rbac-setup "{{email}}"
    @just auth-test-login "{{email}}"
    @just rbac-show-summary
    @just print-success "🎉 Complete RBAC setup finished!"

# Full authentication diagnostics suite
auth-full-diagnostics:
    @just print-info "🔍 Running full authentication diagnostics..."
    @just auth-diagnose
    @just auth-diagnose-frontend
    @just auth-test-session
    @just show-auth-issues
    @just print-success "🎉 Full authentication diagnostics completed!"

# Complete security audit
security-full-audit:
    @just print-info "🛡️ Running complete security audit..."
    @just security-scan
    @just debug-password-hash
    @just investigate-auth
    @just show-auth-improvements
    @just print-success "🎉 Complete security audit finished!"

# Show all summaries and documentation
show-all-summaries:
    @just print-info "📋 Displaying all summaries..."
    @just rbac-show-summary
    @just show-auth-improvements
    @just show-auth-issues
    @just show-login-fixes
    @just show-test-fixes
    @just show-final-resolution
    @just print-success "📋 All summaries displayed!"

# ============================================================================
# Help for New Tasks
# ============================================================================

# Show help for RBAC tasks
help-rbac:
    @echo ""
    @echo "🔐 RBAC (Role-Based Access Control) Tasks:"
    @echo "  rbac-create-table          - Create DynamoDB roles table"
    @echo "  rbac-show-summary          - Show RBAC implementation guide"
    @echo "  rbac-create-admin <email>  - Create admin user"
    @echo "  rbac-check-admin <email>   - Check admin user status"
    @echo "  rbac-delete-admin <email>  - Delete admin user"
    @echo "  rbac-setup <email>         - Complete RBAC setup"
    @echo "  rbac-full-setup <email>    - RBAC setup + testing"
    @echo ""

# Show help for authentication tasks
help-auth:
    @echo ""
    @echo "🔑 Authentication & Security Tasks:"
    @echo "  auth-diagnose              - Run authentication diagnostics"
    @echo "  auth-monitor-logs          - Monitor auth logs in real-time"
    @echo "  auth-monitor-xray          - Monitor X-Ray auth flow"
    @echo "  auth-test-login <email>    - Test user login flow"
    @echo "  auth-test-session          - Test session persistence"
    @echo "  auth-diagnose-frontend     - Diagnose frontend auth issues"
    @echo "  auth-create-bookmarklet    - Create debug bookmarklet"
    @echo "  auth-create-interceptor    - Create log interceptor"
    @echo "  auth-full-diagnostics      - Complete auth diagnostics suite"
    @echo ""

# Show help for production tasks
help-production:
    @echo ""
    @echo "🏭 Production & Security Tasks:"
    @echo "  prod-diagnose-502          - Diagnose production 502 errors"
    @echo "  security-scan              - Run security vulnerability scan"
    @echo "  debug-password-hash        - Debug password hash issues"
    @echo "  investigate-auth           - Investigate auth issues"
    @echo "  security-full-audit        - Complete security audit"
    @echo ""

# Show help for summary tasks
help-summaries:
    @echo ""
    @echo "📋 Summary & Documentation Tasks:"
    @echo "  show-auth-improvements     - Show auth improvements summary"
    @echo "  show-auth-issues           - Show auth issue summary"
    @echo "  show-login-fixes           - Show login fix summary"
    @echo "  show-test-fixes            - Show test fixes summary"
    @echo "  show-final-resolution      - Show final resolution summary"
    @echo "  show-all-summaries         - Show all summaries"
    @echo ""

# Show comprehensive help for all new tasks
help-scripts:
    @just help-rbac
    @just help-auth
    @just help-production
    @just help-summaries
    @echo "🔧 Bash Script Wrappers:"
    @echo "  deploy-frontend-bash       - Deploy frontend (bash)"
    @echo "  run-performance-profiler   - Run performance profiler"
    @echo "  run-optimized-validation   - Run optimized validation"
    @echo "  run-workflow-logger        - Start workflow logger"
    @echo "  detect-execution-mode      - Detect execution mode"
    @echo "  handle-artifacts           - Handle artifacts"
    @echo "  test-artifact-compatibility - Test artifact compatibility"
    @echo ""
    @echo "💡 Quick Start Examples:"
    @echo "  just rbac-full-setup admin@example.com    # Complete RBAC setup"
    @echo "  just auth-full-diagnostics                # Full auth diagnostics"
    @echo "  just security-full-audit                  # Complete security audit"
    @echo "  just show-all-summaries                   # View all documentation"
