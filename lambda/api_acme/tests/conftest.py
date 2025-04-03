import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Set test environment variables
os.environ.setdefault("DYNAMO_TABLE_NAME", "test-table")
os.environ.setdefault("AWS_DEFAULT_REGION", "eu-west-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")


@pytest.fixture
def mock_environment():
    with patch.dict(
        os.environ,
        {
            "DYNAMO_TABLE_NAME": "test_table",
        },
    ):
        yield


@pytest.fixture
def mock_dynamodb():
    with patch("boto3.resource") as mock_resource:
        mock_table = MagicMock()
        mock_resource.return_value.Table.return_value = mock_table
        yield mock_table
