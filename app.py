#!/usr/bin/env python3
import os

import aws_cdk as cdk

from people_register_infrastructure.people_register_infrastructure_stack import PeopleRegisterInfrastructureStack
from people_register_infrastructure.amplify_frontend_stack import AmplifyFrontendStack


app = cdk.App()

# Backend infrastructure (existing)
backend_stack = PeopleRegisterInfrastructureStack(app, "PeopleRegisterInfrastructureStack",
    # Specify the AWS Account and Region for deployment
    env=cdk.Environment(
        account='142728997126',  # AWS Account ID
        region='us-east-1'       # AWS Region
    )
)

# Frontend Amplify stack
frontend_stack = AmplifyFrontendStack(app, "PeopleRegisterAmplifyStack",
    env=cdk.Environment(
        account='142728997126',  # AWS Account ID
        region='us-east-1'       # AWS Region
    )
)

app.synth()
