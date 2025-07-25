#!/bin/bash

# Deploy Frontend Script
# This script builds and deploys the frontend to S3 and invalidates CloudFront cache

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if required tools are installed
check_requirements() {
    print_status "Checking requirements..."
    
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v npm &> /dev/null; then
        print_error "npm is not installed or not in PATH"
        exit 1
    fi
    
    print_status "Requirements check passed"
}

# Get stack outputs
get_stack_outputs() {
    print_status "Getting stack outputs..."
    
    BUCKET_NAME=$(aws cloudformation describe-stacks \
        --stack-name PeopleRegisterInfrastructureStack \
        --query 'Stacks[0].Outputs[?OutputKey==`S3BucketName`].OutputValue' \
        --output text 2>/dev/null || echo "")
    
    DISTRIBUTION_ID=$(aws cloudfront list-distributions \
        --query "DistributionList.Items[?Comment==''].Id" \
        --output text 2>/dev/null || echo "")
    
    API_URL=$(aws cloudformation describe-stacks \
        --stack-name PeopleRegisterInfrastructureStack \
        --query 'Stacks[0].Outputs[?OutputKey==`ApiUrl`].OutputValue' \
        --output text 2>/dev/null || echo "")
    
    if [ -z "$BUCKET_NAME" ]; then
        print_error "Could not retrieve S3 bucket name from stack outputs"
        print_warning "Make sure the infrastructure stack is deployed"
        exit 1
    fi
    
    print_status "S3 Bucket: $BUCKET_NAME"
    print_status "API URL: $API_URL"
    
    if [ -n "$DISTRIBUTION_ID" ]; then
        print_status "CloudFront Distribution ID: $DISTRIBUTION_ID"
    else
        print_warning "Could not retrieve CloudFront distribution ID"
    fi
}

# Build frontend
build_frontend() {
    print_status "Building frontend..."
    
    cd ../people-register-frontend
    
    # Set environment variable for API URL
    if [ -n "$API_URL" ]; then
        export PUBLIC_API_URL="$API_URL"
        echo "PUBLIC_API_URL=$API_URL" > .env
        print_status "Set API URL: $API_URL"
    fi
    
    # Install dependencies if node_modules doesn't exist
    if [ ! -d "node_modules" ]; then
        print_status "Installing dependencies..."
        npm install
    fi
    
    # Build the project
    npm run build
    
    if [ ! -d "dist" ]; then
        print_error "Build failed - dist directory not found"
        exit 1
    fi
    
    print_status "Frontend build completed"
    cd ../people-register-infrastructure
}

# Deploy to S3
deploy_to_s3() {
    print_status "Deploying to S3..."
    
    aws s3 sync ../people-register-frontend/dist/ "s3://$BUCKET_NAME" \
        --delete \
        --cache-control "public, max-age=31536000" \
        --exclude "*.html" \
        --exclude "*.json"
    
    # Upload HTML files with shorter cache
    aws s3 sync ../people-register-frontend/dist/ "s3://$BUCKET_NAME" \
        --delete \
        --cache-control "public, max-age=0, must-revalidate" \
        --include "*.html" \
        --include "*.json"
    
    print_status "Files uploaded to S3"
}

# Invalidate CloudFront cache
invalidate_cloudfront() {
    if [ -n "$DISTRIBUTION_ID" ]; then
        print_status "Invalidating CloudFront cache..."
        
        INVALIDATION_ID=$(aws cloudfront create-invalidation \
            --distribution-id "$DISTRIBUTION_ID" \
            --paths "/*" \
            --query 'Invalidation.Id' \
            --output text)
        
        print_status "CloudFront invalidation created: $INVALIDATION_ID"
        print_status "Cache invalidation may take 5-15 minutes to complete"
    else
        print_warning "Skipping CloudFront invalidation - distribution ID not found"
    fi
}

# Main execution
main() {
    print_status "Starting frontend deployment..."
    
    check_requirements
    get_stack_outputs
    build_frontend
    deploy_to_s3
    invalidate_cloudfront
    
    print_status "Frontend deployment completed successfully!"
    
    if [ -n "$API_URL" ]; then
        FRONTEND_URL=$(aws cloudformation describe-stacks \
            --stack-name PeopleRegisterInfrastructureStack \
            --query 'Stacks[0].Outputs[?OutputKey==`FrontendUrl`].OutputValue' \
            --output text 2>/dev/null || echo "")
        
        if [ -n "$FRONTEND_URL" ]; then
            print_status "Frontend URL: $FRONTEND_URL"
        fi
    fi
}

# Run main function
main "$@"
