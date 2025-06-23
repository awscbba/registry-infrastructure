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
    Duration,
    RemovalPolicy,
    CfnOutput,
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

        # Lambda function for the API - using external file for project management
        api_lambda = _lambda.Function(
            self, "PeopleApiFunction",
            runtime=_lambda.Runtime.PYTHON_3_9,
            handler="api_handler.lambda_handler",
            code=_lambda.Code.from_asset("lambda"),
            environment={
                "PEOPLE_TABLE_NAME": people_table.table_name,
                "PROJECTS_TABLE_NAME": projects_table.table_name,
                "SUBSCRIPTIONS_TABLE_NAME": subscriptions_table.table_name,
            },
            timeout=Duration.seconds(30),
            memory_size=512,
        )

        # Grant Lambda permissions to access DynamoDB tables
        people_table.grant_read_write_data(api_lambda)
        projects_table.grant_read_write_data(api_lambda)
        subscriptions_table.grant_read_write_data(api_lambda)

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
