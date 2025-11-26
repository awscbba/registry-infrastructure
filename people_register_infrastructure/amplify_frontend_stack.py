from aws_cdk import (
    Stack,
    CfnOutput,
)
from constructs import Construct


class AmplifyFrontendStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Reference the existing Amplify app created via AWS CLI
        existing_app_id = "d36qiwhuhsb8gy"
        
        # Outputs
        CfnOutput(
            self, "AmplifyAppId",
            value=existing_app_id,
            description="Amplify App ID",
            export_name="PeopleRegistryAmplifyAppId"
        )

        CfnOutput(
            self, "AmplifyAppUrl",
            value=f"https://main.{existing_app_id}.amplifyapp.com",
            description="Amplify App Production URL",
            export_name="PeopleRegistryAmplifyAppUrl"
        )

        CfnOutput(
            self, "AmplifyConsoleUrl",
            value=f"https://console.aws.amazon.com/amplify/home#{existing_app_id}",
            description="Amplify Console URL",
            export_name="PeopleRegistryAmplifyConsoleUrl"
        )
