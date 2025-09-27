from aws_cdk import (
    Stack,
    aws_amplify_alpha as amplify,
    aws_s3 as s3,
    aws_iam as iam,
    CfnOutput,
    RemovalPolicy,
)
from constructs import Construct


class AmplifyFrontendStack(Stack):
    """
    AWS Amplify stack for hosting the Astro SSR frontend.
    Uses S3 as source since CodeCatalyst is not directly supported.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create S3 bucket for Amplify deployments
        deployment_bucket = s3.Bucket(
            self, "AmplifyDeploymentBucket",
            bucket_name=f"amplify-deployments-d2df6u91uqaaay",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            public_read_access=False,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL
        )

        # Create Amplify App for SSR frontend hosting
        amplify_app = amplify.App(
            self, "PeopleRegistryAmplifyApp",
            app_name="people-registry-frontend",
            description="People Registry Frontend with Astro SSR support - S3 source"
        )

        # Create IAM role for Amplify to access S3
        amplify_role = iam.Role(
            self, "AmplifyServiceRole",
            assumed_by=iam.ServicePrincipal("amplify.amazonaws.com"),
            inline_policies={
                "S3Access": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "s3:GetObject",
                                "s3:GetObjectVersion", 
                                "s3:ListBucket"
                            ],
                            resources=[
                                deployment_bucket.bucket_arn,
                                f"{deployment_bucket.bucket_arn}/*"
                            ]
                        )
                    ]
                )
            }
        )

        # Add bucket policy to allow Amplify service access
        deployment_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("amplify.amazonaws.com")],
                actions=[
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:ListBucket"
                ],
                resources=[
                    deployment_bucket.bucket_arn,
                    f"{deployment_bucket.bucket_arn}/*"
                ]
            )
        )

        # Also allow the account to manage the bucket
        deployment_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.AccountRootPrincipal()],
                actions=["s3:*"],
                resources=[
                    deployment_bucket.bucket_arn,
                    f"{deployment_bucket.bucket_arn}/*"
                ]
            )
        )

        # Outputs
        CfnOutput(
            self, "AmplifyAppId",
            value=amplify_app.app_id,
            description="Amplify App ID for S3-based deployments",
            export_name="PeopleRegistryAmplifyAppId"
        )

        CfnOutput(
            self, "AmplifyConsoleUrl",
            value=f"https://console.aws.amazon.com/amplify/home#/{amplify_app.app_id}",
            description="Amplify Console URL",
            export_name="PeopleRegistryAmplifyConsoleUrl"
        )

        CfnOutput(
            self, "DeploymentBucket",
            value=deployment_bucket.bucket_name,
            description="S3 bucket for Amplify deployment packages",
            export_name="AmplifyDeploymentBucket"
        )

        CfnOutput(
            self, "AmplifyServiceRole",
            value=amplify_role.role_arn,
            description="IAM role for Amplify S3 access",
            export_name="AmplifyServiceRoleArn"
        )
