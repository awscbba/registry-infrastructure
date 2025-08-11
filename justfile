# ============================================================================
# People Registry Infrastructure Deployment (CodeCatalyst)
# ============================================================================
# This justfile handles ONLY infrastructure deployment for CodeCatalyst.
# Frontend deployment is handled by registry-frontend repository.
# API deployment is handled by registry-api repository via ECR images.
# ============================================================================

# Variables
STACK_NAME := "PeopleRegisterInfrastructureStack"
WORK_DIR := "/tmp/people-register-deployment"

# CodeCatalyst repository URLs (update these with your actual URLs)
CODECATALYST_BASE_URL := "https://srinclan@git.us-west-2.codecatalyst.aws/v1/AWSCocha/people-registry"
INFRASTRUCTURE_REPO := CODECATALYST_BASE_URL + "/registry-infrastructure"
API_REPO := CODECATALYST_BASE_URL + "/registry-api"
FRONTEND_REPO := CODECATALYST_BASE_URL + "/register-frontend"

# ============================================================================
# INFRASTRUCTURE DEPLOYMENT
# ============================================================================

# Deploy infrastructure and extract outputs
deploy-infrastructure-full:
    @just print-info "Deploying infrastructure stack..."
    @cdk deploy --require-approval never --outputs-file outputs.json
    @just extract-outputs
    @just print-success "Infrastructure deployment completed!"

# Extract deployment outputs to environment file
extract-outputs:
    @just print-info "Extracting deployment outputs..."
    @if [ ! -f "outputs.json" ]; then \
        just print-error "outputs.json not found. CDK deployment may have failed."; \
        exit 1; \
    fi
    @API_URL=$$(cat outputs.json | jq -r '.{{STACK_NAME}}.ApiUrl // empty'); \
    S3_BUCKET=$$(cat outputs.json | jq -r '.{{STACK_NAME}}.S3BucketName // empty'); \
    DISTRIBUTION_ID=$$(cat outputs.json | jq -r '.{{STACK_NAME}}.DistributionId // empty'); \
    FRONTEND_URL=$$(cat outputs.json | jq -r '.{{STACK_NAME}}.FrontendUrl // empty'); \
    echo "# Deployment Outputs - Generated $(date)" > deployment-outputs.env; \
    echo "API_URL=$$API_URL" >> deployment-outputs.env; \
    echo "S3_BUCKET=$$S3_BUCKET" >> deployment-outputs.env; \
    echo "DISTRIBUTION_ID=$$DISTRIBUTION_ID" >> deployment-outputs.env; \
    echo "FRONTEND_URL=$$FRONTEND_URL" >> deployment-outputs.env; \
    just print-info "API URL: $$API_URL"; \
    just print-info "S3 Bucket: $$S3_BUCKET"; \
    just print-info "Distribution ID: $$DISTRIBUTION_ID"; \
    just print-info "Frontend URL: $$FRONTEND_URL"; \
    just print-success "Outputs extracted to deployment-outputs.env"

# ============================================================================
# TESTING
# ============================================================================

# Test API endpoints
test-api:
    @just print-info "Testing API endpoints..."
    @if [ ! -f "deployment-outputs.env" ]; then \
        just print-error "deployment-outputs.env not found. Run deploy-infrastructure-full first."; \
        exit 1; \
    fi
    @source deployment-outputs.env && \
    if [ -z "$API_URL" ]; then \
        just print-error "API_URL not found in deployment outputs"; \
        exit 1; \
    fi && \
    just print-info "Testing health endpoint: $API_URL/health" && \
    if curl -f -s "$API_URL/health" >/dev/null; then \
        just print-success "API health check passed"; \
    else \
        just print-error "API health check failed"; \
        exit 1; \
    fi

# Create test data in the application
create-test-data:
    @just print-info "Creating test data..."
    @python3 scripts/create_test_data.py

# ============================================================================
# INFORMATION AND UTILITIES
# ============================================================================

# Print deployment summary
print-deployment-summary:
    @just print-info "=== DEPLOYMENT SUMMARY ==="
    @if [ -f "deployment-outputs.env" ]; then \
        source deployment-outputs.env && \
        echo "🚀 Infrastructure: Deployed" && \
        echo "🔗 API URL: $$API_URL" && \
        echo "🎨 Frontend URL: $$FRONTEND_URL" && \
        echo "📦 S3 Bucket: $$S3_BUCKET" && \
        echo "🌐 CloudFront Distribution: $$DISTRIBUTION_ID" && \
        echo "" && \
        echo "📋 Next Steps:" && \
        echo "- API: Deploy using registry-api repository" && \
        echo "- Frontend: Deploy using registry-frontend repository" && \
        echo "- Frontend: Use FRONTEND_URL and API_URL from deployment-outputs.env"; \
    else \
        just print-error "deployment-outputs.env not found. Run deploy-infrastructure-full first."; \
    fi

# Get API URL from CloudFormation outputs
get-api-url:
    @aws cloudformation describe-stacks \
        --stack-name {{STACK_NAME}} \
        --query 'Stacks[0].Outputs[?OutputKey==`ApiUrl`].OutputValue' \
        --output text 2>/dev/null || echo ""

# Get S3 bucket name from CloudFormation outputs
get-bucket-name:
    @aws cloudformation describe-stacks \
        --stack-name {{STACK_NAME}} \
        --query 'Stacks[0].Outputs[?OutputKey==`S3BucketName`].OutputValue' \
        --output text 2>/dev/null || echo ""

# Get CloudFront distribution ID from CloudFormation outputs
get-distribution-id:
    @aws cloudformation describe-stacks \
        --stack-name {{STACK_NAME}} \
        --query 'Stacks[0].Outputs[?OutputKey==`DistributionId`].OutputValue' \
        --output text 2>/dev/null || echo ""

# Get frontend URL from CloudFormation outputs
get-frontend-url:
    @aws cloudformation describe-stacks \
        --stack-name {{STACK_NAME}} \
        --query 'Stacks[0].Outputs[?OutputKey==`FrontendUrl`].OutputValue' \
        --output text 2>/dev/null || echo ""

# ============================================================================
# CDK COMMANDS
# ============================================================================

# Bootstrap CDK
cdk-bootstrap:
    @just print-status "Bootstrapping CDK..."
    @cdk bootstrap

# Deploy CDK stack
cdk-deploy:
    @just print-status "Deploying CDK stack..."
    @cdk deploy

# Destroy CDK stack
cdk-destroy:
    @just print-status "Destroying CDK stack..."
    @cdk destroy

# Show CDK diff
cdk-diff:
    @just print-status "Showing CDK diff..."
    @cdk diff

# Synthesize CDK stack
cdk-synth:
    @just print-status "Synthesizing CDK stack..."
    @cdk synth

# ============================================================================
# RBAC (Role-Based Access Control) Management
# ============================================================================

# Create DynamoDB roles table for RBAC system
rbac-create-table:
    @just print-info "Creating RBAC roles table..."
    @python3 scripts/create_roles_table.py

# Setup complete RBAC system with admin user
rbac-full-setup admin_email:
    @just print-info "Setting up complete RBAC system..."
    @just rbac-create-table
    @python3 scripts/setup_rbac_system.py {{admin_email}}
    @just print-success "RBAC system setup completed for {{admin_email}}"

# ============================================================================
# AUTHENTICATION DIAGNOSTICS
# ============================================================================

# Full authentication diagnostics
auth-full-diagnostics:
    @just print-info "Running full authentication diagnostics..."
    @python3 scripts/auth_diagnostics.py

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Print colored status messages
print-info message:
    @echo "ℹ️  {{message}}"

print-success message:
    @echo "✅ {{message}}"

print-warning message:
    @echo "⚠️  {{message}}"

print-error message:
    @echo "❌ {{message}}"

print-status message:
    @echo "🔄 {{message}}"

# Check if required tools are installed
check-prerequisites:
    @just print-info "Checking prerequisites..."
    @command -v aws >/dev/null 2>&1 || { just print-error "AWS CLI is required but not installed."; exit 1; }
    @command -v cdk >/dev/null 2>&1 || { just print-error "AWS CDK is required but not installed."; exit 1; }
    @command -v jq >/dev/null 2>&1 || { just print-error "jq is required but not installed."; exit 1; }
    @command -v python3 >/dev/null 2>&1 || { just print-error "Python 3 is required but not installed."; exit 1; }
    @just print-success "All prerequisites are installed"

# Validate deployment status
validate-deployment:
    @just print-info "Validating deployment..."
    @just test-api
    @just print-success "Deployment validation completed"

# ============================================================================
# HELP
# ============================================================================

# Show help information
help:
    @echo "🏗️  People Registry Infrastructure Deployment (CodeCatalyst)"
    @echo ""
    @echo "🚀 Main Commands:"
    @echo "  deploy-infrastructure-full     - Deploy infrastructure and extract outputs"
    @echo "  test-api                       - Test API endpoints"
    @echo "  create-test-data               - Create sample data"
    @echo "  print-deployment-summary       - Show deployment information"
    @echo ""
    @echo "🔧 CDK Commands:"
    @echo "  cdk-bootstrap                  - Bootstrap CDK"
    @echo "  cdk-deploy                     - Deploy CDK stack"
    @echo "  cdk-destroy                    - Destroy CDK stack"
    @echo "  cdk-diff                       - Show CDK diff"
    @echo "  cdk-synth                      - Synthesize CDK stack"
    @echo ""
    @echo "🔐 RBAC Commands:"
    @echo "  rbac-create-table              - Create roles table"
    @echo "  rbac-full-setup <email>        - Setup RBAC with admin user"
    @echo ""
    @echo "🔍 Diagnostics:"
    @echo "  auth-full-diagnostics          - Run authentication diagnostics"
    @echo "  validate-deployment            - Validate deployment status"
    @echo ""
    @echo "📖 Usage Examples:"
    @echo "  just deploy-infrastructure-full        # Deploy infrastructure"
    @echo "  just test-api                          # Test API endpoints"
    @echo "  just rbac-full-setup admin@example.com # Setup RBAC system"
    @echo ""
    @echo "⚠️  CodeCatalyst Multi-Repository Deployment:"
    @echo "  1. Deploy infrastructure: registry-infrastructure repository"
    @echo "  2. Deploy API: registry-api repository (uses ECR images)"
    @echo "  3. Deploy frontend: registry-frontend repository (uses S3/CloudFront)"

# Default recipe
default: help
