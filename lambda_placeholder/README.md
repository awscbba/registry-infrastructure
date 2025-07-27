# Lambda Placeholder Directory

This directory contains minimal placeholder code for Lambda functions created by the CDK infrastructure.

## Architecture

- **Infrastructure (this repo)**: Creates AWS resources including Lambda functions with placeholder code
- **API Code (registry-api repo)**: Deploys actual FastAPI application code to the Lambda functions

## Deployment Flow

1. CDK deploys infrastructure with placeholder Lambda code
2. registry-api repository deploys actual application code using `main.lambda_handler`
3. Both Lambda functions (API and Auth) use the same handler from the FastAPI application

## Handler Configuration

Both Lambda functions are configured to use:
- **Handler**: `main.lambda_handler`
- **Runtime**: Python 3.9
- **Code Source**: Deployed by registry-api repository

## Benefits

- Clean separation of concerns
- Independent deployment cycles
- Modern FastAPI + Mangum architecture
- Single source of truth for API code