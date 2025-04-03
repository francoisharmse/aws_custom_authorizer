from aws_cdk import (
    Stack,
)
from aws_cdk import (
    aws_route53 as route53,
)
from constructs import Construct


class Route53Stack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        domain_name: str,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.hosted_zone = route53.HostedZone(
            self,
            "WebAppZone",
            zone_name=domain_name,
        )
