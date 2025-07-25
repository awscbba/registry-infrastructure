#!/usr/bin/env python3
import os

import aws_cdk as cdk

from people_register_infrastructure.people_register_infrastructure_stack import PeopleRegisterInfrastructureStack


app = cdk.App()
PeopleRegisterInfrastructureStack(app, "PeopleRegisterInfrastructureStack",
    # Specify the AWS Account and Region for deployment
    env=cdk.Environment(
        account='142728997126',  # AWS Account ID
        region='us-east-1'       # AWS Region
    )
)

app.synth()
