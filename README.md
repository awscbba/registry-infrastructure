
# People Register Infrastructure

AWS CDK infrastructure code for the People Register microservices application.

## Architecture

This CDK stack deploys a complete serverless architecture:

### Backend Services
- **AWS Lambda**: Serverless API functions (Python 3.11)
- **Amazon DynamoDB**: NoSQL database for people data
- **API Gateway**: REST API with CORS support
- **Lambda Layer**: Shared dependencies optimization

### Frontend Hosting
- **Amazon S3**: Static website hosting
- **CloudFront**: Global CDN with custom error pages
- **Origin Access Identity**: Secure S3 access

### Security & Performance
- **CORS Configuration**: Proper cross-origin resource sharing
- **HTTPS Redirect**: Secure connections enforced
- **Caching**: Optimized content delivery
- **IAM Roles**: Least privilege access

## Prerequisites

1. **AWS CLI** configured with appropriate credentials
2. **AWS CDK** installed globally:
   ```bash
   npm install -g aws-cdk
   ```
3. **Python 3.11+** installed
4. **Docker** (for Lambda layer building)

## Setup

1. **Create and activate virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Bootstrap CDK** (first time only):
   ```bash
   cdk bootstrap
   ```

## Deployment

### Deploy Infrastructure

```bash
# Synthesize CloudFormation template
cdk synth

# Deploy the stack
cdk deploy

# Deploy with approval bypass (use with caution)
cdk deploy --require-approval never
```

### Deploy Frontend

After infrastructure deployment:

1. **Build the frontend**:
   ```bash
   cd ../people-register-frontend
   npm run build
   ```

2. **Upload to S3**:
   ```bash
   aws s3 sync dist/ s3://YOUR-BUCKET-NAME --delete
   ```

3. **Invalidate CloudFront cache**:
   ```bash
   aws cloudfront create-invalidation --distribution-id YOUR-DISTRIBUTION-ID --paths "/*"
   ```

## Environment Variables

The stack creates the following environment variables for Lambda:

- `PEOPLE_TABLE_NAME`: DynamoDB table name

## Outputs

After deployment, the stack provides:

- **ApiUrl**: API Gateway endpoint URL
- **FrontendUrl**: CloudFront distribution URL  
- **S3BucketName**: Frontend hosting bucket name
- **DynamoDBTableName**: Database table name

## Configuration

### Production Considerations

For production deployment, modify:

1. **Removal Policies**: Change to `RETAIN` for data persistence
2. **CORS Origins**: Restrict to specific domains
3. **CloudFront Price Class**: Consider global distribution
4. **DynamoDB**: Enable backup and monitoring
5. **Lambda**: Configure reserved concurrency and monitoring

### Custom Domain (Optional)

To use a custom domain:

1. **Certificate Manager**: Create SSL certificate
2. **Route 53**: Configure DNS records
3. **CloudFront**: Add alternate domain names

## Monitoring

The stack includes basic monitoring. For production, add:

- **CloudWatch Alarms**: API errors, Lambda duration
- **X-Ray Tracing**: Distributed tracing
- **AWS Config**: Compliance monitoring
- **Cost Budgets**: Spending alerts

## Security

Security features included:

- **IAM Roles**: Least privilege access
- **S3 Block Public Access**: Prevent accidental exposure
- **HTTPS Only**: Secure connections enforced
- **CORS**: Controlled cross-origin access

## Useful Commands

- `cdk ls`: List all stacks
- `cdk synth`: Synthesize CloudFormation template
- `cdk deploy`: Deploy stack to AWS
- `cdk diff`: Compare deployed stack with current state
- `cdk destroy`: Delete the stack
- `cdk docs`: Open CDK documentation

## Troubleshooting

### Common Issues

1. **Bootstrap Required**: Run `cdk bootstrap` first
2. **Permissions**: Ensure AWS credentials have sufficient permissions
3. **Region**: Verify correct AWS region configuration
4. **Dependencies**: Check all requirements are installed

### Logs

- **Lambda Logs**: CloudWatch Logs `/aws/lambda/function-name`
- **API Gateway**: Enable logging in API Gateway console
- **CloudFront**: Access logs can be enabled

## Cost Optimization

- **DynamoDB**: Pay-per-request billing
- **Lambda**: Pay per invocation and duration
- **S3**: Standard storage class
- **CloudFront**: Price Class 100 (US/Europe)

Estimated monthly cost for low traffic: $5-15 USD

## Development Workflow

1. **Make changes** to infrastructure code
2. **Test locally** with `cdk synth`
3. **Deploy to dev** environment first
4. **Test thoroughly** before production
5. **Deploy to production** with proper approvals
