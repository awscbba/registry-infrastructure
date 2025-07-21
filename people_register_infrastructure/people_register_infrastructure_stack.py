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
            point_in_time_recovery=True,
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
            point_in_time_recovery=True,
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
            point_in_time_recovery=True,
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
            point_in_time_recovery=True,
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
            point_in_time_recovery=True,
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
            point_in_time_recovery=True,
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
            point_in_time_recovery=True,
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
            point_in_time_recovery=True,
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
            point_in_time_recovery=True,
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
            point_in_time_recovery=True,
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

        # Lambda function for the API - Final Enhanced API handler (working version)
        api_lambda = _lambda.Function(
            self, "PeopleApiFunction",
            runtime=_lambda.Runtime.PYTHON_3_9,
            handler="enhanced_api_handler.lambda_handler",  # Final working enhanced handler
            code=_lambda.Code.from_asset("lambda", bundling=BundlingOptions(
                image=_lambda.Runtime.PYTHON_3_9.bundling_image,
                command=[
                    "bash", "-c",
                    "pip install -r requirements.txt -t /asset-output && cp -au . /asset-output"
                ]
            )),
            environment={
                "PEOPLE_TABLE_NAME": people_table.table_name,
                "PROJECTS_TABLE_NAME": projects_table.table_name,
                "SUBSCRIPTIONS_TABLE_NAME": subscriptions_table.table_name,
                "PASSWORD_RESET_TOKENS_TABLE_NAME": password_reset_tokens_table.table_name,
                "AUDIT_LOGS_TABLE_NAME": audit_logs_table.table_name,
                "EMAIL_TRACKING_TABLE": email_tracking_table.table_name,
                "PASSWORD_HISTORY_TABLE": password_history_table.table_name,
                "SESSION_TRACKING_TABLE": session_tracking_table.table_name,
                "RATE_LIMIT_TABLE_NAME": rate_limit_table.table_name,
                "CSRF_TOKEN_TABLE_NAME": csrf_token_table.table_name,
                "CSRF_SECRET": "production-csrf-secret-change-this-value",  # Change in production
                "SES_FROM_EMAIL": "noreply@people-register.local",  # Replace with your verified email
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
        email_tracking_table.grant_read_write_data(api_lambda)
        password_history_table.grant_read_write_data(api_lambda)
        session_tracking_table.grant_read_write_data(api_lambda)
        rate_limit_table.grant_read_write_data(api_lambda)
        csrf_token_table.grant_read_write_data(api_lambda)
        
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

        # Lambda integration
        lambda_integration = apigateway.LambdaIntegration(
            api_lambda,
            request_templates={"application/json": '{"statusCode": "200"}'}
        )

        # API Gateway routes
        # Health check
        health_resource = api.root.add_resource("health")
        health_resource.add_method("GET", lambda_integration)

        # People resource
        people_resource = api.root.add_resource("people")
        people_resource.add_method("GET", lambda_integration)  # List people
        people_resource.add_method("POST", lambda_integration)  # Create person

        # Individual person resource
        person_resource = people_resource.add_resource("{id}")
        person_resource.add_method("GET", lambda_integration)  # Get person
        person_resource.add_method("PUT", lambda_integration)  # Update person
        person_resource.add_method("DELETE", lambda_integration)  # Delete person

        # Projects resource (new)
        projects_resource = api.root.add_resource("projects")
        projects_resource.add_method("GET", lambda_integration)  # List projects
        projects_resource.add_method("POST", lambda_integration)  # Create project

        # Individual project resource
        project_resource = projects_resource.add_resource("{id}")
        project_resource.add_method("GET", lambda_integration)  # Get project
        project_resource.add_method("PUT", lambda_integration)  # Update project
        project_resource.add_method("DELETE", lambda_integration)  # Delete project

        # Project subscribers
        subscribers_resource = project_resource.add_resource("subscribers")
        subscribers_resource.add_method("GET", lambda_integration)  # Get project subscribers

        # Project subscription management
        subscribe_resource = project_resource.add_resource("subscribe")
        subscribe_person_resource = subscribe_resource.add_resource("{personId}")
        subscribe_person_resource.add_method("POST", lambda_integration)  # Subscribe person to project

        unsubscribe_resource = project_resource.add_resource("unsubscribe")
        unsubscribe_person_resource = unsubscribe_resource.add_resource("{personId}")
        unsubscribe_person_resource.add_method("DELETE", lambda_integration)  # Unsubscribe person from project

        # Subscriptions resource (new)
        subscriptions_resource = api.root.add_resource("subscriptions")
        subscriptions_resource.add_method("GET", lambda_integration)  # List subscriptions
        subscriptions_resource.add_method("POST", lambda_integration)  # Create subscription

        # Individual subscription resource
        subscription_resource = subscriptions_resource.add_resource("{id}")
        subscription_resource.add_method("DELETE", lambda_integration)  # Delete subscription

        # Admin resource (new)
        admin_resource = api.root.add_resource("admin")
        dashboard_resource = admin_resource.add_resource("dashboard")
        dashboard_resource.add_method("GET", lambda_integration)  # Get admin dashboard
        
        # Password reset cleanup (admin endpoint) - simplified
        password_reset_admin_resource = admin_resource.add_resource("password-reset")
        password_reset_admin_resource.add_method("POST", lambda_integration)  # Cleanup expired tokens

        # Authentication resource (new) - simplified routing
        auth_resource = api.root.add_resource("auth")
        
        # Single password-reset endpoint that handles all operations via HTTP method and body
        password_reset_resource = auth_resource.add_resource("password-reset")
        password_reset_resource.add_method("POST", lambda_integration)  # All password reset operations
        password_reset_resource.add_method("GET", lambda_integration)   # Token validation via query params

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
            ),
            default_root_object="index.html",
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_http_status=200,
                    response_page_path="/index.html",
                    ttl=Duration.minutes(30),
                )
            ],
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
