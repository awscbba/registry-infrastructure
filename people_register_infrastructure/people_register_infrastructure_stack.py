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

        # Lambda function for the API - simple approach without bundling
        api_lambda = _lambda.Function(
            self, "PeopleApiFunction",
            runtime=_lambda.Runtime.PYTHON_3_11,
            handler="index.lambda_handler",
            code=_lambda.Code.from_inline("""
import json
import boto3
import uuid
import os
from datetime import datetime

dynamodb = boto3.resource('dynamodb')

def lambda_handler(event, context):
    print(f"Event: {json.dumps(event)}")
    
    # Get table name from environment
    table_name = os.environ.get('PEOPLE_TABLE_NAME', 'PeopleTable')
    table = dynamodb.Table(table_name)
    
    # Extract HTTP method and path
    http_method = event.get('httpMethod', 'GET')
    path = event.get('path', '/')
    path_parameters = event.get('pathParameters') or {}
    
    try:
        if path == '/health':
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key'
                },
                'body': json.dumps({'status': 'healthy', 'service': 'people-register-api'})
            }
        
        elif path == '/people':
            if http_method == 'GET':
                # List all people
                response = table.scan()
                people = response.get('Items', [])
                return {
                    'statusCode': 200,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
                        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key'
                    },
                    'body': json.dumps(people)
                }
            
            elif http_method == 'POST':
                # Create new person
                body = json.loads(event.get('body', '{}'))
                person_id = str(uuid.uuid4())
                now = datetime.utcnow().isoformat()
                
                person = {
                    'id': person_id,
                    'firstName': body.get('firstName'),
                    'lastName': body.get('lastName'),
                    'email': body.get('email'),
                    'phone': body.get('phone'),
                    'dateOfBirth': body.get('dateOfBirth'),
                    'address': body.get('address', {}),
                    'createdAt': now,
                    'updatedAt': now
                }
                
                table.put_item(Item=person)
                
                return {
                    'statusCode': 201,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
                        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key'
                    },
                    'body': json.dumps(person)
                }
        
        elif path.startswith('/people/'):
            person_id = path_parameters.get('id')
            if not person_id:
                return {
                    'statusCode': 400,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({'error': 'Person ID is required'})
                }
            
            if http_method == 'GET':
                # Get person by ID
                response = table.get_item(Key={'id': person_id})
                if 'Item' not in response:
                    return {
                        'statusCode': 404,
                        'headers': {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        },
                        'body': json.dumps({'error': 'Person not found'})
                    }
                
                return {
                    'statusCode': 200,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
                        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key'
                    },
                    'body': json.dumps(response['Item'])
                }
            
            elif http_method == 'PUT':
                # Update person
                body = json.loads(event.get('body', '{}'))
                now = datetime.utcnow().isoformat()
                
                # Check if person exists
                response = table.get_item(Key={'id': person_id})
                if 'Item' not in response:
                    return {
                        'statusCode': 404,
                        'headers': {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        },
                        'body': json.dumps({'error': 'Person not found'})
                    }
                
                # Update the person
                person = response['Item']
                person.update({
                    'firstName': body.get('firstName', person.get('firstName')),
                    'lastName': body.get('lastName', person.get('lastName')),
                    'email': body.get('email', person.get('email')),
                    'phone': body.get('phone', person.get('phone')),
                    'dateOfBirth': body.get('dateOfBirth', person.get('dateOfBirth')),
                    'address': body.get('address', person.get('address', {})),
                    'updatedAt': now
                })
                
                table.put_item(Item=person)
                
                return {
                    'statusCode': 200,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
                        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key'
                    },
                    'body': json.dumps(person)
                }
            
            elif http_method == 'DELETE':
                # Delete person
                response = table.delete_item(
                    Key={'id': person_id},
                    ReturnValues='ALL_OLD'
                )
                
                if 'Attributes' not in response:
                    return {
                        'statusCode': 404,
                        'headers': {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        },
                        'body': json.dumps({'error': 'Person not found'})
                    }
                
                return {
                    'statusCode': 204,
                    'headers': {
                        'Access-Control-Allow-Origin': '*',
                        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
                        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key'
                    },
                    'body': ''
                }
        
        # Default response for unmatched routes
        return {
            'statusCode': 404,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': 'Route not found'})
        }
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': 'Internal server error'})
        }
"""),
            environment={
                "PEOPLE_TABLE_NAME": people_table.table_name,
            },
            timeout=Duration.seconds(30),
            memory_size=512,
        )

        # Grant Lambda permissions to access DynamoDB
        people_table.grant_read_write_data(api_lambda)

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
