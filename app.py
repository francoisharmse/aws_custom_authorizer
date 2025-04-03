#!/usr/bin/env python3
import os

import aws_cdk as cdk

from stacks import route53_stack
from stacks.dynamodb import DynamoDBStack
from stacks.lambda_stack import ApiLambdaStack
from stacks.web_app import WebAppStack


def load_config():
    # Get the environment defined at the command line
    config = app.node.try_get_context("config")
    if not config:
        raise ValueError("Please specify a config using -c config=<environment>")

    # Load configurations for the specified environment from cdk.json
    config_values = app.node.try_get_context(config)
    if not config_values:
        raise ValueError(f"No configuration found for {config}")
    return config_values


app = cdk.App()
config = load_config()
env = cdk.Environment(
    account=os.getenv("AWS_ACCOUNT_ID"), region=os.getenv("CDK_DEFAULT_REGION")
)

route53_stack = route53_stack.Route53Stack(
    app,
    "ACMERoute53Stack",
    env=env,
    domain_name=config["domain_name"],
)

dynamo_stack = DynamoDBStack(
    app,
    "ACMEDynamoDBStack",
    env=env,
    description="Creates a DynamoDB table",
    env_name=os.getenv("ENVIRONMENT", "dev"),
)

lambda_stack = ApiLambdaStack(
    app,
    "ACMEApiLambdaStack",
    env=env,
    domain_name=config["domain_name"],
    dynamo_table_name=dynamo_stack.dynamo_table.table_name,
    azure_tenant_id=os.getenv("AZURE_AD_TENANT_ID", "none"),
    azure_policy_name=os.getenv("AZURE_AD_PRIMARY_USERFLOW", "none"),
    azure_client_id=os.getenv("AZURE_AD_CLIENT_ID", "none"),
    hosted_zone=route53_stack.hosted_zone,
)

web_app_stack = WebAppStack(
    app,
    "ACMEWebAppStack",
    env=env,
    description="Creates a web app running inside S3 with Cloudfront",
    domain_name=config["domain_name"],
    env_name=os.getenv("ENVIRONMENT", "dev"),
    hosted_zone=route53_stack.hosted_zone,
)

lambda_stack.add_dependency(route53_stack)
lambda_stack.add_dependency(dynamo_stack)
web_app_stack.add_dependency(lambda_stack)


app.synth()
