# AWS Testing Setup Guide

## 🔧 Configure AWS Credentials

To test your deployed API locally, you need AWS credentials configured:

### Option 1: AWS CLI Configure
```bash
aws configure
```
Enter your:
- AWS Access Key ID
- AWS Secret Access Key  
- Default region: `us-west-2`
- Default output format: `json`

### Option 2: AWS SSO (if using SSO)
```bash
aws configure sso
```

### Option 3: Environment Variables
```bash
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
export AWS_DEFAULT_REGION=us-west-2
```

## 🧪 Test Your Deployed API

Once credentials are configured:

```bash
cd people-register-infrastructure

# Get deployment outputs
aws cloudformation describe-stacks \
  --stack-name PeopleRegisterInfrastructureStack \
  --region us-west-2 \
  --query 'Stacks[0].Outputs'

# Or use the justfile
just extract-outputs
just test-api
```

## 🎯 Manual API Testing

If you know your API Gateway URL, test directly:

```bash
# Health check
curl https://YOUR-API-ID.execute-api.us-west-2.amazonaws.com/prod/health

# List people (should be empty initially)
curl https://YOUR-API-ID.execute-api.us-west-2.amazonaws.com/prod/people

# Create a person
curl -X POST https://YOUR-API-ID.execute-api.us-west-2.amazonaws.com/prod/people \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "John",
    "lastName": "Doe", 
    "email": "john.doe@example.com",
    "phone": "+1-555-0123",
    "dateOfBirth": "1990-01-15",
    "address": {
      "street": "123 Main St",
      "city": "Anytown",
      "state": "CA",
      "zipCode": "12345",
      "country": "USA"
    }
  }'
```

## 🚀 Frontend Deployment

After API testing, deploy the frontend:

```bash
# Navigate to frontend directory
cd ../people-register-frontend

# Install dependencies
npm install

# Set API URL (get from CloudFormation outputs)
echo "PUBLIC_API_URL=https://YOUR-API-ID.execute-api.us-west-2.amazonaws.com/prod" > .env

# Build frontend
npm run build

# Deploy to S3 (get bucket name from CloudFormation outputs)
aws s3 sync dist/ s3://YOUR-BUCKET-NAME --delete

# Invalidate CloudFront cache
aws cloudfront create-invalidation \
  --distribution-id YOUR-DISTRIBUTION-ID \
  --paths "/*"
```
