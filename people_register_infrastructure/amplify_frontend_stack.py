from aws_cdk import (
    Stack,
    aws_amplify_alpha as amplify,
    CfnOutput,
)
from constructs import Construct


class AmplifyFrontendStack(Stack):
    """
    AWS Amplify stack for hosting the Astro SSR frontend.
    Note: CodeCatalyst integration requires manual setup in Amplify Console.
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create Amplify App for SSR frontend hosting
        amplify_app = amplify.App(
            self, "PeopleRegistryAmplifyApp",
            app_name="people-registry-frontend",
            description="People Registry Frontend with Astro SSR support - CodeCatalyst integration"
        )

        # Outputs
        CfnOutput(
            self, "AmplifyAppId",
            value=amplify_app.app_id,
            description="Amplify App ID - Connect to CodeCatalyst manually in console",
            export_name="PeopleRegistryAmplifyAppId"
        )

        CfnOutput(
            self, "AmplifyConsoleUrl",
            value=f"https://console.aws.amazon.com/amplify/home#/{amplify_app.app_id}",
            description="Amplify Console - Connect to CodeCatalyst repository",
            export_name="PeopleRegistryAmplifyConsoleUrl"
        )

        CfnOutput(
            self, "CodeCatalystSetupInstructions",
            value="1. Open Amplify Console 2. Connect CodeCatalyst repo 3. Set build root: registry-frontend 4. Deploy",
            description="Manual setup steps for CodeCatalyst integration",
            export_name="AmplifyCodeCatalystSetup"
        )
