import aws_cdk as core
import aws_cdk.assertions as assertions

from people_register_infrastructure.people_register_infrastructure_stack import PeopleRegisterInfrastructureStack

# example tests. To run these tests, uncomment this file along with the example
# resource in people_register_infrastructure/people_register_infrastructure_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = PeopleRegisterInfrastructureStack(app, "people-register-infrastructure")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
