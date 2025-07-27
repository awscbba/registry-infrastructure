# Lambda Handler Update - Permanent Architecture Changes

## Overview
Updated the CDK infrastructure to permanently use `main.lambda_handler` from the registry-api deployment, implementing a clean separation between infrastructure and application code.

## Changes Made

### 1. CDK Stack Updates
- **Handler Configuration**: Changed from `enhanced_api_handler.lambda_handler` to `main.lambda_handler`
- **Code Source**: Updated to use `lambda_placeholder` directory instead of bundling from `lambda/`
- **Both Functions**: Applied changes to both `PeopleApiFunction` and `AuthFunction`

### 2. Placeholder Structure
Created `lambda_placeholder/` directory with:
- `main.py`: Minimal placeholder handler
- `requirements.txt`: Empty requirements file
- `README.md`: Documentation of the architecture

### 3. Architecture Benefits
- **Clean Separation**: Infrastructure manages AWS resources, registry-api manages code
- **Independent Deployments**: API team can deploy without infrastructure changes
- **Modern Stack**: FastAPI + Mangum + uv deployment pipeline
- **Single Handler**: Both Lambda functions use the same FastAPI application

## Deployment Flow

### Current State
1. CDK creates Lambda functions with placeholder code
2. registry-api deploys actual FastAPI code using `main.lambda_handler`
3. Both functions route through the same FastAPI application

### Next Steps
1. Deploy CDK changes: `cdk deploy`
2. Test registry-api deployment to ensure handler works
3. Remove old `lambda/` directory (cleanup)

## Files Modified
- `people_register_infrastructure_stack.py`: Updated Lambda function configurations
- `lambda_placeholder/`: New placeholder directory structure

## Testing
- CDK compilation successful
- Ready for deployment and testing with registry-api

## Rollback Plan
If needed, can revert to previous handler by:
1. Changing handler back to `enhanced_api_handler.lambda_handler`
2. Updating code source back to `lambda/` directory
3. Re-deploying CDK stack