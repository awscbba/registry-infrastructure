from aws_cdk import (
    Stack,
    aws_lambda as _lambda,
    aws_apigateway as apigateway,
    aws_dynamodb as dynamodb,
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as cloudfront_origins,
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

        # ========================================
        # STANDARDIZED TABLES (V2) - Clean Architecture
        # ========================================
        
        # Standardized People Table with consistent camelCase schema
        people_table_v2 = dynamodb.Table(
            self, "PeopleTableV2",
            table_name="PeopleTableV2",
            partition_key=dynamodb.Attribute(
                name="id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,  # Use RETAIN for production
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
        )

        # Add GSI for querying people by email (required for uniqueness checks)
        people_table_v2.add_global_secondary_index(
            index_name="EmailIndex",
            partition_key=dynamodb.Attribute(
                name="email",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # Standardized Projects Table with consistent camelCase schema
        projects_table_v2 = dynamodb.Table(
            self, "ProjectsTableV2",
            table_name="ProjectsTableV2",
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

        # Add GSI for querying projects by status
        projects_table_v2.add_global_secondary_index(
            index_name="StatusIndex",
            partition_key=dynamodb.Attribute(
                name="status",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # Add GSI for querying projects by category
        projects_table_v2.add_global_secondary_index(
            index_name="CategoryIndex",
            partition_key=dynamodb.Attribute(
                name="category",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # Standardized Subscriptions Table with consistent camelCase schema
        subscriptions_table_v2 = dynamodb.Table(
            self, "SubscriptionsTableV2",
            table_name="SubscriptionsTableV2",
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

        # Add GSI for querying subscriptions by project
        subscriptions_table_v2.add_global_secondary_index(
            index_name="ProjectIndex",
            partition_key=dynamodb.Attribute(
                name="projectId",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # Add GSI for querying subscriptions by person
        subscriptions_table_v2.add_global_secondary_index(
            index_name="PersonIndex",
            partition_key=dynamodb.Attribute(
                name="personId",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # Add GSI for querying subscriptions by status
        subscriptions_table_v2.add_global_secondary_index(
            index_name="StatusIndex",
            partition_key=dynamodb.Attribute(
                name="status",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # DynamoDB Table for storing project form submissions (Dynamic Form Builder)
        project_submissions_table = dynamodb.Table(
            self, "ProjectSubmissionsTable",
            table_name="ProjectSubmissions",
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

        # Add GSI for querying submissions by project
        project_submissions_table.add_global_secondary_index(
            index_name="ProjectIndex",
            partition_key=dynamodb.Attribute(
                name="projectId",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # Add GSI for querying submissions by person
        project_submissions_table.add_global_secondary_index(
            index_name="PersonIndex",
            partition_key=dynamodb.Attribute(
                name="personId",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        # S3 Bucket for project images (Dynamic Form Builder)
        project_images_bucket = s3.Bucket(
            self, "ProjectImagesBucket",
            bucket_name=f"people-registry-project-images-{self.account}-{self.region}",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            cors=[s3.CorsRule(
                allowed_methods=[s3.HttpMethods.GET, s3.HttpMethods.PUT, s3.HttpMethods.POST],
                allowed_origins=["*"],  # Configure for your domain in production
                allowed_headers=["*"],
                max_age=3000
            )],
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="DeleteIncompleteMultipartUploads",
                    abort_incomplete_multipart_upload_after=Duration.days(1)
                )
            ]
        )

        # CloudFront Distribution for project images
        project_images_distribution = cloudfront.Distribution(
            self, "ProjectImagesDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=cloudfront_origins.S3Origin(project_images_bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
            ),
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,  # Use only North America and Europe
            comment="CloudFront distribution for project images"
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
                # Legacy tables (for backward compatibility)
                "PEOPLE_TABLE_NAME": people_table.table_name,
                "AUDIT_LOGS_TABLE_NAME": audit_logs_table.table_name,
                "PASSWORD_RESET_TOKENS_TABLE_NAME": password_reset_tokens_table.table_name,
                
                # Standardized V2 tables (required for authentication)
                "PEOPLE_TABLE_V2_NAME": people_table_v2.table_name,
                
                # Additional tables needed for auth functionality
                "LOCKOUT_TABLE_NAME": account_lockout_table.table_name,
                "EMAIL_TRACKING_TABLE": email_tracking_table.table_name,
                "PASSWORD_HISTORY_TABLE": password_history_table.table_name,
                "SESSION_TRACKING_TABLE": session_tracking_table.table_name,
                "RATE_LIMIT_TABLE_NAME": rate_limit_table.table_name,
                "CSRF_TOKEN_TABLE_NAME": csrf_token_table.table_name,
                
                # Auth configuration
                "JWT_SECRET": "your-jwt-secret-change-in-production-please",
                "JWT_EXPIRATION_HOURS": "24",
                
                # Email and frontend configuration
                "CSRF_SECRET": "production-csrf-secret-change-this-value",
                "SES_FROM_EMAIL": "noreply@cbba.cloud.org.bo",
                "FRONTEND_URL": "https://registry.cbba.cloud.org.bo",
            }
        )
        
        # Grant permissions to Auth Lambda
        people_table.grant_read_write_data(auth_lambda)
        people_table_v2.grant_read_write_data(auth_lambda)  # CRITICAL FIX: Grant access to V2 table
        audit_logs_table.grant_read_write_data(auth_lambda)
        password_reset_tokens_table.grant_read_write_data(auth_lambda)
        
        # Grant access to additional tables needed for auth functionality
        account_lockout_table.grant_read_write_data(auth_lambda)
        email_tracking_table.grant_read_write_data(auth_lambda)
        password_history_table.grant_read_write_data(auth_lambda)
        session_tracking_table.grant_read_write_data(auth_lambda)
        rate_limit_table.grant_read_write_data(auth_lambda)
        csrf_token_table.grant_read_write_data(auth_lambda)
        
        # CRITICAL FIX: Grant Auth Lambda access to roles table for RBAC functionality
        roles_table.grant_read_data(auth_lambda)
        
        # CRITICAL FIX: Grant Auth Lambda access to account lockout table
        account_lockout_table.grant_read_write_data(auth_lambda)
        
        # Grant Auth Lambda permissions to send emails via SES (for password reset emails)
        auth_lambda.add_to_role_policy(
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
                    # Base tables (required for Scan operations)
                    people_table.table_arn,
                    people_table_v2.table_arn,
                    audit_logs_table.table_arn,
                    password_reset_tokens_table.table_arn,
                    roles_table.table_arn,
                    account_lockout_table.table_arn,
                    email_tracking_table.table_arn,
                    password_history_table.table_arn,
                    session_tracking_table.table_arn,
                    rate_limit_table.table_arn,
                    csrf_token_table.table_arn,
                    
                    # Table indexes (GSI)
                    people_table.table_arn + "/index/*",
                    people_table_v2.table_arn + "/index/*",
                    audit_logs_table.table_arn + "/index/*",
                    roles_table.table_arn + "/index/*",
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
                # Legacy tables (for backward compatibility during migration)
                "PEOPLE_TABLE_NAME": people_table.table_name,
                "PROJECTS_TABLE_NAME": projects_table.table_name,
                "SUBSCRIPTIONS_TABLE_NAME": subscriptions_table.table_name,
                
                # Standardized tables (V2) - Clean Architecture
                "PEOPLE_TABLE_V2_NAME": people_table_v2.table_name,
                "PROJECTS_TABLE_V2_NAME": projects_table_v2.table_name,
                "SUBSCRIPTIONS_TABLE_V2_NAME": subscriptions_table_v2.table_name,
                
                # Dynamic Form Builder tables
                "PROJECT_SUBMISSIONS_TABLE_NAME": project_submissions_table.table_name,
                
                # S3 and CloudFront for project images
                "PROJECT_IMAGES_BUCKET_NAME": project_images_bucket.bucket_name,
                "PROJECT_IMAGES_CLOUDFRONT_DOMAIN": project_images_distribution.distribution_domain_name,
                
                # JWT Configuration (must match auth function)
                "JWT_SECRET": "your-jwt-secret-change-in-production-please",
                "JWT_EXPIRATION_HOURS": "48",
                
                # Other tables
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
                "FRONTEND_URL": "https://registry.cbba.cloud.org.bo",  # Production domain
            },
            timeout=Duration.seconds(30),
            memory_size=512,
        )

        # Grant Lambda permissions to access DynamoDB tables
        # Legacy tables (for backward compatibility during migration)
        people_table.grant_read_write_data(api_lambda)
        projects_table.grant_read_write_data(api_lambda)
        subscriptions_table.grant_read_write_data(api_lambda)
        
        # Standardized tables (V2) - Clean Architecture
        people_table_v2.grant_read_write_data(api_lambda)
        projects_table_v2.grant_read_write_data(api_lambda)
        subscriptions_table_v2.grant_read_write_data(api_lambda)
        
        # Dynamic Form Builder tables
        project_submissions_table.grant_read_write_data(api_lambda)
        
        # Grant S3 permissions for project images
        project_images_bucket.grant_read_write(api_lambda)
        
        # Other tables
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
                    # Base tables (required for Scan operations)
                    people_table.table_arn,
                    projects_table.table_arn,
                    subscriptions_table.table_arn,
                    people_table_v2.table_arn,
                    projects_table_v2.table_arn,
                    subscriptions_table_v2.table_arn,
                    audit_logs_table.table_arn,
                    password_reset_tokens_table.table_arn,
                    roles_table.table_arn,
                    account_lockout_table.table_arn,
                    email_tracking_table.table_arn,
                    password_history_table.table_arn,
                    session_tracking_table.table_arn,
                    rate_limit_table.table_arn,
                    csrf_token_table.table_arn,
                    
                    # Table indexes (GSI)
                    people_table.table_arn + "/index/*",
                    password_reset_tokens_table.table_arn + "/index/*",
                    roles_table.table_arn + "/index/*",
                    people_table_v2.table_arn + "/index/*",
                    projects_table_v2.table_arn + "/index/*",
                    subscriptions_table_v2.table_arn + "/index/*",
                    
                    # Wildcard for any other tables/indexes
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

        # API Gateway - Updated 2025-11-25 for comprehensive CORS support
        api = apigateway.RestApi(
            self, "PeopleRegisterApi",
            rest_api_name="People Register API",
            description="API for managing people registration",
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=apigateway.Cors.ALL_METHODS,
                allow_headers=[
                    "Content-Type",
                    "X-Amz-Date",
                    "Authorization",
                    "X-Api-Key",
                    "X-Amz-Security-Token",
                    "X-Requested-With",
                    "Accept",
                    "Accept-Language",
                    "Content-Language",
                ],
                expose_headers=[
                    "Access-Control-Allow-Origin",
                    "Access-Control-Allow-Headers",
                ],
                allow_credentials=True,
                max_age=Duration.hours(1),
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
    
    // If URI has a file extension, serve it as-is (assets like .js, .css, .png, etc.)
    if (uri.includes('.')) {
        return request;
    }
    
    // For all other paths (React Router routes), serve index.html
    // This includes paths like /subscribe/voluntarios/, /admin, /login, etc.
    request.uri = '/index.html';
    
    return request;
}
            """),
            comment="Rewrites URLs to serve index.html files for static site routing"
        )

        # CloudFront Distribution
        distribution = cloudfront.Distribution(
            self, "FrontendDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=cloudfront_origins.S3Origin(
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

        # Standardized Tables (V2) Outputs
        CfnOutput(
            self, "PeopleTableV2Name",
            value=people_table_v2.table_name,
            description="Standardized People DynamoDB table name (V2)",
            export_name="PeopleTableV2Name"
        )

        CfnOutput(
            self, "ProjectsTableV2Name",
            value=projects_table_v2.table_name,
            description="Standardized Projects DynamoDB table name (V2)",
            export_name="ProjectsTableV2Name"
        )

        CfnOutput(
            self, "SubscriptionsTableV2Name",
            value=subscriptions_table_v2.table_name,
            description="Standardized Subscriptions DynamoDB table name (V2)",
            export_name="SubscriptionsTableV2Name"
        )

        # Dynamic Form Builder Outputs
        CfnOutput(
            self, "ProjectSubmissionsTableName",
            value=project_submissions_table.table_name,
            description="Project Submissions DynamoDB table name",
            export_name="ProjectSubmissionsTableName"
        )

        CfnOutput(
            self, "ProjectImagesBucketName",
            value=project_images_bucket.bucket_name,
            description="S3 bucket for project images",
            export_name="ProjectImagesBucketName"
        )

        CfnOutput(
            self, "ProjectImagesCloudFrontDomain",
            value=project_images_distribution.distribution_domain_name,
            description="CloudFront domain for project images",
            export_name="ProjectImagesCloudFrontDomain"
        )
