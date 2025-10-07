from aws_cdk import (
    Stack,
    aws_amplify_alpha as amplify,
    aws_iam as iam,
    CfnOutput,
)
from constructs import Construct


class AmplifyFrontendStack(Stack):
    """
    AWS Amplify stack for hosting the Astro SSR frontend.
    
    PRODUCTION STATUS (Working Setup):
    - App ID: d2df6u91uqaaay  
    - URL: https://main.d2df6u91uqaaay.amplifyapp.com
    - Platform: WEB_COMPUTE (SSR enabled)
    - Source: GitHub (awscbba/registry-frontend)
    - Framework: Astro with astro-aws-amplify adapter
    - Build: Auto-detected Astro build
    - Role: arn:aws:iam::142728997126:role/PeopleRegisterAmplifyStac-PeopleRegistryAmplifyAppR-E0KRtWJGrpSU
    
    This CDK stack manages the existing Amplify app configuration.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create IAM role for Amplify with proper permissions
        amplify_role = iam.Role(
            self, "PeopleRegistryAmplifyAppRole",
            assumed_by=iam.ServicePrincipal("amplify.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess-Amplify")
            ]
        )

        # Create Amplify App matching current configuration
        amplify_app = amplify.App(
            self, "PeopleRegistryAmplifyApp",
            app_name="people-registry-frontend",
            description="People Registry Frontend with Astro SSR support - S3 source",
            source_code_provider=amplify.GitHubSourceCodeProvider(
                owner="awscbba",
                repository="registry-frontend",
                oauth_token=None  # Uses GitHub App connection
            ),
            platform=amplify.Platform.WEB_COMPUTE,
            role=amplify_role,
            environment_variables={
                "HOST": "0.0.0.0",
                "NODE_ENV": "production", 
                "PORT": "3000",
                "PUBLIC_API_URL": "https://2t9blvt2c1.execute-api.us-east-1.amazonaws.com/prod",
                "_CUSTOM_IMAGE": "amplify:al2023",
                "_LIVE_UPDATES": "[{\"name\":\"Amplify CLI\",\"pkg\":\"@aws-amplify/cli\",\"type\":\"npm\",\"version\":\"latest\"}]"
            },
            custom_rules=[
                amplify.CustomRule(
                    source="/<*>",
                    target="/index.html",
                    status=amplify.RedirectStatus.NOT_FOUND_REWRITE
                )
            ],
            auto_branch_creation=amplify.AutoBranchCreation(
                patterns=["*", "*/**", "deploy/**", "feature/**", "fix/**"],
                auto_build=True,
                stage=amplify.Stage.DEVELOPMENT
            ),
            auto_branch_deletion=True
        )

        # Main production branch
        main_branch = amplify_app.add_branch(
            "main",
            stage=amplify.Stage.PRODUCTION,
            auto_build=True,
            environment_variables={
                "AMPLIFY_BACKEND_APP_ID": "d2df6u91uqaaay",
                "USER_BRANCH": "staging"
            }
        )

        # Outputs
        CfnOutput(
            self, "AmplifyAppId",
            value=amplify_app.app_id,
            description="Amplify App ID",
            export_name="PeopleRegistryAmplifyAppId"
        )

        CfnOutput(
            self, "AmplifyAppUrl",
            value=f"https://main.{amplify_app.app_id}.amplifyapp.com",
            description="Amplify App Production URL",
            export_name="PeopleRegistryAmplifyAppUrl"
        )

        CfnOutput(
            self, "AmplifyConsoleUrl",
            value=f"https://console.aws.amazon.com/amplify/home#/{amplify_app.app_id}",
            description="Amplify Console URL",
            export_name="PeopleRegistryAmplifyConsoleUrl"
        )

        CfnOutput(
            self, "AmplifyServiceRoleArn",
            value=amplify_role.role_arn,
            description="IAM role for Amplify service",
            export_name="AmplifyServiceRoleArn"
        )
