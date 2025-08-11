from aws_cdk import (
    Stack,
    aws_lambda as _lambda,
    aws_apigateway as apigateway,
    aws_dynamodb as dynamodb,
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_s3_deployment as s3deploy,
    aws_iam as iam,
    aws_ses as ses,
    aws_ecr as ecr,
    Duration,
    RemovalPolicy,
    CfnOutput,
    BundlingOptions,
)
from constructs import Construct
import os


class PeopleRegisterInfrastructureStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # DynamoDB Table for storing people data
        people_table = dynamodb.Table(
            self, "PeopleTable",
            table_name="PeopleTable",
            partition_key=dynamodb.Attribute(
                name="id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,  # Use RETAIN for production
            # point_in_time_recovery=True,  # Temporarily disabled due to CDK API changes
        )

        # Add GSI for querying people by email (required for uniqueness checks)
        people_table.add_global_secondary_index(
            index_name="EmailIndex",
            partition_key=dynamodb.Attribute(
                name="email",
                type=dynamodb.AttributeType.STRING
            ),
        )

        # DynamoDB Table for storing projects
        projects_table = dynamodb.Table(
            self, "ProjectsTable",
            table_name="ProjectsTable",
            partition_key=dynamodb.Attribute(
                name="id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
        )

        # DynamoDB Table for storing subscriptions (many-to-many relationship)
        subscriptions_table = dynamodb.Table(
            self, "SubscriptionsTable",
            table_name="SubscriptionsTable",
            partition_key=dynamodb.Attribute(
                name="id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
        )

        # DynamoDB Table for storing password reset tokens
        password_reset_tokens_table = dynamodb.Table(
            self, "PasswordResetTokensTable",
            table_name="PasswordResetTokensTable",
            partition_key=dynamodb.Attribute(
                name="resetToken",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            time_to_live_attribute="expiresAt",  # TTL configuration
        )

        # Add GSI for querying reset tokens by email
        password_reset_tokens_table.add_global_secondary_index(
            index_name="EmailIndex",
            partition_key=dynamodb.Attribute(
                name="email",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # DynamoDB Table for email delivery tracking
        email_tracking_table = dynamodb.Table(
            self, "EmailTrackingTable",
            table_name="EmailTrackingTable",
            partition_key=dynamodb.Attribute(
                name="emailId",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            time_to_live_attribute="ttl"  # Auto-delete old email records
        )

        # Add GSI for querying emails by recipient
        email_tracking_table.add_global_secondary_index(
            index_name="RecipientIndex",
            partition_key=dynamodb.Attribute(
                name="recipientEmail",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="createdAt",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # Add GSI for querying emails by status
        email_tracking_table.add_global_secondary_index(
            index_name="StatusIndex",
            partition_key=dynamodb.Attribute(
                name="status",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="createdAt",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # Add GSI for querying emails by template type
        email_tracking_table.add_global_secondary_index(
            index_name="TemplateIndex",
            partition_key=dynamodb.Attribute(
                name="templateType",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="createdAt",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # DynamoDB Table for password history tracking
        password_history_table = dynamodb.Table(
            self, "PasswordHistoryTable",
            table_name="PasswordHistoryTable",
            partition_key=dynamodb.Attribute(
                name="userId",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="createdAt",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            time_to_live_attribute="ttl"  # Auto-delete old password history
        )

        # DynamoDB Table for session tracking
        session_tracking_table = dynamodb.Table(
            self, "SessionTrackingTable", 
            table_name="SessionTrackingTable",
            partition_key=dynamodb.Attribute(
                name="sessionId",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            time_to_live_attribute="ttl"  # Auto-delete expired sessions
        )

        # Add GSI for querying sessions by user
        session_tracking_table.add_global_secondary_index(
            index_name="UserIndex",
            partition_key=dynamodb.Attribute(
                name="userId",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="createdAt",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # DynamoDB Table for rate limiting (Task 20 - Production Security Hardening)
        rate_limit_table = dynamodb.Table(
            self, "RateLimitTable",
            table_name="RateLimitTable",
            partition_key=dynamodb.Attribute(
                name="id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            time_to_live_attribute="ttl"  # Auto-cleanup old rate limit records
        )

        # Add GSI for querying rate limits by endpoint
        rate_limit_table.add_global_secondary_index(
            index_name="EndpointIndex",
            partition_key=dynamodb.Attribute(
                name="endpoint",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="lastReset",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # DynamoDB Table for CSRF token storage (Task 20 - Production Security Hardening)
        csrf_token_table = dynamodb.Table(
            self, "CSRFTokenTable",
            table_name="CSRFTokenTable",
            partition_key=dynamodb.Attribute(
                name="token",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            time_to_live_attribute="ttl"  # Auto-cleanup expired CSRF tokens
        )

        # Add GSI for querying CSRF tokens by session
        csrf_token_table.add_global_secondary_index(
            index_name="SessionIndex",
            partition_key=dynamodb.Attribute(
                name="session_id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="created_at",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # DynamoDB Table for role-based access control (RBAC)
        # Reference existing table instead of creating new one
        roles_table = dynamodb.Table.from_table_name(
            self, "RolesTable",
            table_name="people-registry-roles"
        )

        # DynamoDB Table for storing audit logs
        audit_logs_table = dynamodb.Table(
            self, "AuditLogsTable",
            table_name="AuditLogsTable",
            partition_key=dynamodb.Attribute(
                name="id",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
        )

        # DynamoDB Table for account lockout tracking
        account_lockout_table = dynamodb.Table(
            self, "AccountLockoutTable",
            table_name="AccountLockoutTable",
            partition_key=dynamodb.Attribute(
                name="personId",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            time_to_live_attribute="ttl"  # Auto-cleanup old lockout records
        )

        # Add GSI for querying audit logs by person
        audit_logs_table.add_global_secondary_index(
            index_name="PersonIndex",
            partition_key=dynamodb.Attribute(
                name="personId",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # Add GSI for querying audit logs by action type
        audit_logs_table.add_global_secondary_index(
            index_name="ActionIndex",
            partition_key=dynamodb.Attribute(
                name="action",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # Add GSI for querying subscriptions by project
        subscriptions_table.add_global_secondary_index(
            index_name="ProjectIndex",
            partition_key=dynamodb.Attribute(
                name="projectId",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # Add GSI for querying subscriptions by person
        subscriptions_table.add_global_secondary_index(
            index_name="PersonIndex",
            partition_key=dynamodb.Attribute(
                name="personId",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # AWS SES Configuration for Email Services
        # Note: For development, we'll rely on manual SES setup
        # In production, you would verify your domain and email addresses through the AWS Console
        
        # For now, we'll skip creating SES resources via CDK and rely on:
        # 1. Manual email verification in SES console
        # 2. Lambda permissions to send emails
        # 3. Environment variables for configuration

        # ARCHITECTURE NOTE: Lambda Code Deployment
        # This CDK stack creates the Lambda functions with placeholder code.
        # The actual FastAPI application code is deployed separately by the registry-api repository
        # using its own deployment pipeline (uv + zip deployment).
        # This separation allows:
        # - Infrastructure team manages AWS resources
        # - API team manages application code independently
        # - Faster development cycles for API changes

        # Authentication Lambda Function - Uses container deployment from ECR
        auth_lambda = _lambda.Function(
            self, "AuthFunction",
            code=_lambda.Code.from_ecr_image(
                repository=ecr.Repository.from_repository_name(
                    self, "AuthLambdaECRRepo", "registry-api-lambda"
                ),
                tag_or_digest="latest"
            ),
            handler=_lambda.Handler.FROM_IMAGE,
            runtime=_lambda.Runtime.FROM_IMAGE,
            timeout=Duration.seconds(30),
            memory_size=512,
            # tracing=_lambda.Tracing.ACTIVE,  # Temporarily disabled due to recursion issue
            environment={
                "PEOPLE_TABLE_NAME": people_table.table_name,
                "AUDIT_LOGS_TABLE_NAME": audit_logs_table.table_name,
                "JWT_SECRET": "your-jwt-secret-change-in-production-please",
                "JWT_EXPIRATION_HOURS": "24",
            }
        )
        
        # Grant permissions to Auth Lambda
        people_table.grant_read_write_data(auth_lambda)
        audit_logs_table.grant_read_write_data(auth_lambda)
        
        # Add explicit permissions for GSI operations (EmailIndex) for auth lambda
        auth_lambda.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "dynamodb:Query",
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:Scan"
                ],
                resources=[
                    people_table.table_arn + "/index/*",
                    audit_logs_table.table_arn + "/index/*",
                    f"arn:aws:dynamodb:{self.region}:{self.account}:table/*/index/*"
                ]
            )
        )

        # Lambda function for the API - Uses container deployment from ECR
        api_lambda = _lambda.Function(
            self, "PeopleApiFunction",
            code=_lambda.Code.from_ecr_image(
                repository=ecr.Repository.from_repository_name(
                    self, "ApiLambdaECRRepo", "registry-api-lambda"
                ),
                tag_or_digest="latest"
            ),
            handler=_lambda.Handler.FROM_IMAGE,
            runtime=_lambda.Runtime.FROM_IMAGE,
            # tracing=_lambda.Tracing.ACTIVE,  # Temporarily disabled due to recursion issue
            environment={
                "PEOPLE_TABLE_NAME": people_table.table_name,
                "PROJECTS_TABLE_NAME": projects_table.table_name,
                "SUBSCRIPTIONS_TABLE_NAME": subscriptions_table.table_name,
                "PASSWORD_RESET_TOKENS_TABLE_NAME": password_reset_tokens_table.table_name,
                "AUDIT_LOGS_TABLE_NAME": audit_logs_table.table_name,
                "LOCKOUT_TABLE_NAME": account_lockout_table.table_name,
                "EMAIL_TRACKING_TABLE": email_tracking_table.table_name,
                "PASSWORD_HISTORY_TABLE": password_history_table.table_name,
                "SESSION_TRACKING_TABLE": session_tracking_table.table_name,
                "RATE_LIMIT_TABLE_NAME": rate_limit_table.table_name,
                "CSRF_TOKEN_TABLE_NAME": csrf_token_table.table_name,
                "CSRF_SECRET": "production-csrf-secret-change-this-value",  # Change in production
                "SES_FROM_EMAIL": "noreply@cbba.cloud.org.bo",  # Production verified domain email
                "FRONTEND_URL": "https://d28z2il3z2vmpc.cloudfront.net",  # Will be updated after CloudFront creation
            },
            timeout=Duration.seconds(30),
            memory_size=512,
        )

        # Grant Lambda permissions to access DynamoDB tables
        people_table.grant_read_write_data(api_lambda)
        projects_table.grant_read_write_data(api_lambda)
        subscriptions_table.grant_read_write_data(api_lambda)
        password_reset_tokens_table.grant_read_write_data(api_lambda)
        audit_logs_table.grant_read_write_data(api_lambda)
        account_lockout_table.grant_read_write_data(api_lambda)
        email_tracking_table.grant_read_write_data(api_lambda)
        password_history_table.grant_read_write_data(api_lambda)
        session_tracking_table.grant_read_write_data(api_lambda)
        rate_limit_table.grant_read_write_data(api_lambda)
        csrf_token_table.grant_read_write_data(api_lambda)
        roles_table.grant_read_write_data(api_lambda)  # RBAC roles table
        
        # Add explicit permissions for GSI operations (EmailIndex)
        api_lambda.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "dynamodb:Query",
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:Scan"
                ],
                resources=[
                    people_table.table_arn + "/index/*",
                    password_reset_tokens_table.table_arn + "/index/*",
                    roles_table.table_arn + "/index/*",  # RBAC roles table GSI
                    f"arn:aws:dynamodb:{self.region}:{self.account}:table/*/index/*"
                ]
            )
        )
        
        # Grant Lambda permissions to send emails via SES
        api_lambda.add_to_role_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "ses:SendEmail",
                    "ses:SendRawEmail",
                    "ses:SendTemplatedEmail",
                    "ses:GetSendQuota",
                    "ses:GetSendStatistics",
                    "ses:GetAccountSendingEnabled"
                ],
                resources=["*"]  # In production, restrict to specific SES resources
            )
        )

        # API Gateway
        api = apigateway.RestApi(
            self, "PeopleRegisterApi",
            rest_api_name="People Register API",
            description="API for managing people registration",
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=apigateway.Cors.ALL_METHODS,
                allow_headers=["Content-Type", "X-Amz-Date", "Authorization", "X-Api-Key"],
            ),
        )

        # Router Lambda Function - Uses container deployment from ECR
        router_lambda = _lambda.Function(
            self, "RouterFunction",
            code=_lambda.Code.from_ecr_image(
                repository=ecr.Repository.from_repository_name(
                    self, "RouterLambdaECRRepo", "registry-router-lambda"
                ),
                tag_or_digest="latest"
            ),
            handler=_lambda.Handler.FROM_IMAGE,
            runtime=_lambda.Runtime.FROM_IMAGE,
            timeout=Duration.seconds(30),
            memory_size=256,
            # tracing=_lambda.Tracing.ACTIVE,  # Temporarily disabled due to recursion issue
            environment={
                "AUTH_FUNCTION_NAME": auth_lambda.function_name,
                "API_FUNCTION_NAME": api_lambda.function_name,
            }
        )
        
        # Grant router permission to invoke other Lambda functions
        auth_lambda.grant_invoke(router_lambda)
        api_lambda.grant_invoke(router_lambda)
        
        # Single Lambda integration for the router
        router_integration = apigateway.LambdaIntegration(
            router_lambda,
            request_templates={"application/json": '{"statusCode": "200"}'}
        )

        # API Gateway routes - Simple routing via Router Lambda
        # This solves the Lambda policy size limit issue by having minimal API Gateway configuration
        
        # Catch-all resource that forwards all requests to router Lambda
        proxy_resource = api.root.add_resource("{proxy+}")
        proxy_resource.add_method("ANY", router_integration)
        
        # Root level methods (for paths like /health, /auth, etc.)
        api.root.add_method("ANY", router_integration)

        # S3 Bucket for hosting the frontend
        frontend_bucket = s3.Bucket(
            self, "FrontendBucket",
            bucket_name=f"people-register-frontend-{self.account}-{self.region}",
            public_read_access=False,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,  # Use RETAIN for production
        )

        # Origin Access Identity for CloudFront
        origin_access_identity = cloudfront.OriginAccessIdentity(
            self, "FrontendOAI",
            comment="OAI for People Register Frontend"
        )

        # Grant CloudFront access to S3 bucket
        frontend_bucket.grant_read(origin_access_identity)

        # CloudFront Function for URL rewriting to support clean URLs
        url_rewrite_function = cloudfront.Function(
            self, "UrlRewriteFunction",
            code=cloudfront.FunctionCode.from_inline("""
function handler(event) {
    var request = event.request;
    var uri = request.uri;
    
    // Handle root path
    if (uri === '/') {
        return request;
    }
    
    // If URI doesn't have an extension and doesn't end with /
    if (!uri.includes('.') && !uri.endsWith('/')) {
        // Check if it's a known directory path
        if (uri === '/admin' || uri === '/login' || uri === '/dashboard' || uri.startsWith('/subscribe/')) {
            request.uri = uri + '/index.html';
        }
    }
    // If URI ends with / but isn't root
    else if (uri.endsWith('/') && uri !== '/') {
        request.uri = uri + 'index.html';
    }
    
    return request;
}
            """),
            comment="Rewrites URLs to serve index.html files for static site routing"
        )

        # CloudFront Distribution
        distribution = cloudfront.Distribution(
            self, "FrontendDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(
                    frontend_bucket,
                    origin_access_identity=origin_access_identity
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD,
                cached_methods=cloudfront.CachedMethods.CACHE_GET_HEAD,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                function_associations=[
                    cloudfront.FunctionAssociation(
                        function=url_rewrite_function,
                        event_type=cloudfront.FunctionEventType.VIEWER_REQUEST
                    )
                ]
            ),
            default_root_object="index.html",
            # Removed error_responses to allow proper static site routing
            # Added CloudFront Function to handle clean URLs automatically
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
        )

        # Outputs
        CfnOutput(
            self, "ApiUrl",
            value=api.url,
            description="API Gateway URL",
            export_name="PeopleRegisterApiUrl"
        )

        CfnOutput(
            self, "FrontendUrl",
            value=f"https://{distribution.distribution_domain_name}",
            description="CloudFront Distribution URL",
            export_name="PeopleRegisterFrontendUrl"
        )

        CfnOutput(
            self, "S3BucketName",
            value=frontend_bucket.bucket_name,
            description="S3 Bucket for frontend hosting",
            export_name="PeopleRegisterS3Bucket"
        )

        CfnOutput(
            self, "DynamoDBTableName",
            value=people_table.table_name,
            description="DynamoDB table name",
            export_name="PeopleRegisterTableName"
        )

        CfnOutput(
            self, "PasswordResetTokensTableName",
            value=password_reset_tokens_table.table_name,
            description="Password Reset Tokens DynamoDB table name",
            export_name="PasswordResetTokensTableName"
        )

        CfnOutput(
            self, "AuditLogsTableName",
            value=audit_logs_table.table_name,
            description="Audit Logs DynamoDB table name",
            export_name="AuditLogsTableName"
        )
