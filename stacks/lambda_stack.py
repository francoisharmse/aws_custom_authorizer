import logging

from aws_cdk import (
    CfnOutput,
    Duration,
    RemovalPolicy,
    aws_apigateway as apigw,
    aws_certificatemanager as acm,
    Stack,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_route53 as route53,
    aws_route53_targets as targets,
)
from constructs import Construct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ApiLambdaStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        domain_name: str,
        dynamo_table_name: str,
        azure_tenant_id: str,
        azure_policy_name: str,
        azure_client_id: str,
        hosted_zone: route53.HostedZone,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        api_domain_name = f"api.{domain_name}"

        api_lambda_layer = _lambda.LayerVersion(
            self,
            "ACMEApiLambdaLayer",
            code=_lambda.Code.from_asset(
                "requirements/api_acme/api_acme.zip"
            ),
            compatible_runtimes=[_lambda.Runtime.PYTHON_3_12],
        )

        api_lambda = _lambda.Function(
            self,
            "ACMEApi",
            function_name="ACMEApi",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="handler.lambda_handler",
            code=_lambda.Code.from_asset("lambda/api_acme"),
            timeout=Duration.seconds(60),
            layers=[api_lambda_layer],
            environment={
                "DYNAMO_TABLE_NAME": dynamo_table_name,
            },
        )

        dynamo_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:GetItem",
                "dynamodb:BatchGetItem",
                "dynamodb:BatchWriteItem",
                "dynamodb:DescribeTable",
                "dynamodb:Query",
                "dynamodb:Scan",
            ],
            resources=[
                "arn:aws:dynamodb:*:*:table/acme-*",
            ],
        )
        log_policy = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            resources=["*"],
        )

        api_lambda.add_to_role_policy(dynamo_policy)
        api_lambda.add_to_role_policy(log_policy)

        log_group = logs.LogGroup(self, "ApiGwAccessLogs")
        api = apigw.RestApi(
            self,
            "ACMEApiGW",
            rest_api_name="ACMEApiGW",
            default_cors_preflight_options={
                "allow_origins": apigw.Cors.ALL_ORIGINS,
                "allow_methods": apigw.Cors.ALL_METHODS,
                "allow_headers": apigw.Cors.DEFAULT_HEADERS,
                "allow_credentials": True,
            },
            deploy=True,
            deploy_options=apigw.StageOptions(
                stage_name="prod",
                logging_level=apigw.MethodLoggingLevel.INFO,
                access_log_destination=apigw.LogGroupLogDestination(log_group),
                access_log_format=apigw.AccessLogFormat.clf(),
                data_trace_enabled=True,
                tracing_enabled=True,
                metrics_enabled=True,
            ),
            cloud_watch_role=True,
        )

        auth_lambda_layer = _lambda.LayerVersion(
            self,
            "AuthApiLambdaLayer",
            code=_lambda.Code.from_asset(
                "requirements/api_authenticator/api_authenticator.zip"
            ),
            compatible_runtimes=[_lambda.Runtime.PYTHON_3_12],
        )

        auth_lambda = _lambda.Function(
            self,
            "ACMEApiAuthenticator",
            function_name="ACMEApiAuthenticator",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="handler.lambda_handler",
            code=_lambda.Code.from_asset("lambda/api_authenticator"),
            layers=[auth_lambda_layer],
            timeout=Duration.seconds(30),
            environment={
                "AZURE_TENANT_ID": azure_tenant_id,
                "AZURE_POLICY_NAME": azure_policy_name,
                "AZURE_APP_CLIENT_ID": azure_client_id,
            },
        )

        auth = apigw.TokenAuthorizer(
            self,
            "ACMECustomAuthorizer",
            handler=auth_lambda,
            identity_source=apigw.IdentitySource.header("Authorization"),
            results_cache_ttl=Duration.seconds(300),
        )

        any_resource = api.root.add_resource("{proxy+}")
        any_resource.add_method(
            "ANY",
            apigw.LambdaIntegration(api_lambda),
            authorizer=auth,
            authorization_type=apigw.AuthorizationType.CUSTOM,
        )

        certificate = acm.DnsValidatedCertificate(
            self,
            "ACMEApiCert",
            domain_name=api_domain_name,
            subject_alternative_names=[f"*.{api_domain_name}"],
            hosted_zone=hosted_zone,
        )
        certificate.apply_removal_policy(RemovalPolicy.DESTROY)

        custom_domain = apigw.DomainName(
            self,
            "ACMEApiDomain",
            domain_name=api_domain_name,
            certificate=certificate,
            endpoint_type=apigw.EndpointType.REGIONAL,
            security_policy=apigw.SecurityPolicy.TLS_1_2,
        )

        apigw.BasePathMapping(
            self,
            "ACMEApiDomainMapping",
            domain_name=custom_domain,
            rest_api=api,
        )

        route53.ARecord(
            self,
            "ACMEApiAliasRecord",
            zone=hosted_zone,
            target=route53.RecordTarget.from_alias(
                targets.ApiGatewayDomain(custom_domain)
            ),
            record_name="api",
        )

        CfnOutput(self, "DomainName", value=custom_domain.domain_name)
