from aws_cdk import (
    Stack,
)
from aws_cdk import (
    aws_dynamodb as dynamodb,
)
from constructs import Construct


class DynamoDBStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        env_name: str,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.dynamo_table = dynamodb.Table(
            self,
            f"ACMETable-{env_name}",
            table_name=f"acme-{env_name}",
            partition_key=dynamodb.Attribute(
                name="userId", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
        )
