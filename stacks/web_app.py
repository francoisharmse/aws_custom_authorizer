from aws_cdk import (
    Duration,
    RemovalPolicy,
    Stack,
)
from aws_cdk import (
    aws_certificatemanager as acm,
    aws_cloudfront as cloudfront,
    aws_s3 as s3,
    aws_cloudfront_origins as cloudfront_origins,
    aws_s3_deployment as s3deploy,
    aws_iam as iam,
    aws_route53 as route53,
    aws_route53_targets as route53_targets,
)
from constructs import Construct


class WebAppStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        domain_name: str,
        env_name: str,
        hosted_zone: route53.HostedZone,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # If the domain name contains aws.acme.com, create a delegation record
        if domain_name.endswith("acme.com"):
            parent_hosted_zone = route53.HostedZone.from_hosted_zone_id(
                self,
                "ParentHostedZone",
                hosted_zone_id="Z07453461NUH0H36P4UJ8",
            )

            parent_hosted_zone_editor_role = iam.Role.from_role_arn(
                self,
                "DelegationRole",
                role_arn=f"arn:aws:iam::285863493715:role/HostedZoneDelegationRole{self.account}",
            )

            route53.CrossAccountZoneDelegationRecord(
                self,
                "DelegationRecord",
                delegated_zone=hosted_zone,
                parent_hosted_zone_id=parent_hosted_zone.hosted_zone_id,
                delegation_role=parent_hosted_zone_editor_role,
                ttl=Duration.minutes(5),
            )

        certificate = acm.DnsValidatedCertificate(
            self,
            "SiteCertificate",
            domain_name=domain_name,
            subject_alternative_names=[f"*.{domain_name}"],
            hosted_zone=hosted_zone,
            region="us-east-1",  # Cloudfront only checks this region for certificates
        )

        certificate.apply_removal_policy(RemovalPolicy.DESTROY)

        site_bucket = s3.Bucket(
            self,
            "WebAppBucket",
            bucket_name=domain_name.replace(".", "-"),
            public_read_access=False,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            access_control=s3.BucketAccessControl.PRIVATE,
            website_index_document="index.html",
            website_error_document="index.html",
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
        )

        distribution = cloudfront.Distribution(
            self,
            "ACMEDistribution",
            certificate=certificate,
            default_root_object="index.html",
            domain_names=[domain_name],
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_http_status=200,
                    response_page_path="/index.html",
                    ttl=Duration.seconds(10),
                ),
                cloudfront.ErrorResponse(
                    http_status=403,
                    response_http_status=200,
                    response_page_path="/index.html",
                    ttl=Duration.seconds(10),
                ),
            ],
            default_behavior=cloudfront.BehaviorOptions(
                origin=cloudfront_origins.S3BucketOrigin.with_origin_access_control(
                    site_bucket
                ),
                compress=True,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            ),
        )

        route53.ARecord(
            self,
            "ACMESiteAliasRecord",
            zone=hosted_zone,
            record_name=domain_name,
            target=route53.RecordTarget.from_alias(
                route53_targets.CloudFrontTarget(distribution)
            ),
        )

        # Copy the index.html file from test_web_app folder to the s3 bucket
        s3deploy.BucketDeployment(
            self,
            "ACMEWebAppDeployment",
            sources=[s3deploy.Source.asset("out")],
            destination_bucket=site_bucket,
            distribution=distribution,
        )
