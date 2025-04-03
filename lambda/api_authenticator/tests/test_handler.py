import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from api_authenticator.handler import (
    generate_policy,
    get_azure_signing_keys,
    get_key_for_token,
    lambda_handler,
)

# Test data
TEST_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6InF3ZXJ0eXVpb3Bhc2RmZ2hqa2x6eGN2Ym5tMTIzNDU2In0.eyJzdWIiOiJtb2NreUB2aXRlbnMubmwiLCJhdWQiOiJtb2NreV9hdWQiLCJuYW1lIjoiTW9ja3kgTWUiLCJpYXQiOjE3MzQxMDMxMzZ9.HD762IxEUnojOfLy1oga-l1-DOCltQp327Cvon0dzVgsjPYg5QMJjRYHsGJxu3eaIFqJLuMenww-dxkIivp9zQ"
TEST_KEY_ID = "qwertyuiopasdfghjklzxcvbnm123456"
TEST_USER_ID = "mocky@vitens.nl"
TEST_METHOD_ARN = "arn:aws:execute-api:us-west-2:123456789012:api123/test/GET/resource"

# Mock RSA key in JWK format
MOCK_RSA_KEY = {
    "kty": "RSA",
    "kid": TEST_KEY_ID,
    "use": "sig",
    "x5c": [
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc/BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ/2W-5JsGY4Hc5n9yBXArwl93lqt7/RN5w6Cf0h4QyQ5v-65YGjQR0/FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G/xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgwIDAQAB"
    ],
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e": "AQAB",
}


@pytest.fixture
def mock_signing_keys():
    return [MOCK_RSA_KEY]


@pytest.fixture
def mock_environment():
    with patch.dict(
        os.environ,
        {
            "AZURE_APP_CLIENT_ID": "test_client_id",
            "AZURE_TENANT_ID": "test_tenant_id",
            "AZURE_POLICY_NAME": "test_policy",
        },
    ):
        yield


def test_get_azure_signing_keys(mock_environment):
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {"keys": [{"kid": TEST_KEY_ID}]}
        mock_get.return_value = mock_response

        keys = get_azure_signing_keys()
        assert keys == [{"kid": TEST_KEY_ID}]
        mock_get.assert_called_once()


def test_get_key_for_token(mock_signing_keys):
    with patch("jwt.get_unverified_header") as mock_header:
        mock_header.return_value = {"kid": TEST_KEY_ID}

        key = get_key_for_token(TEST_TOKEN, mock_signing_keys)
        assert key == mock_signing_keys[0]


def test_generate_policy():
    policy = generate_policy(TEST_USER_ID, "Allow", TEST_METHOD_ARN)

    assert policy["principalId"] == TEST_USER_ID
    assert policy["policyDocument"]["Version"] == "2012-10-17"
    assert len(policy["policyDocument"]["Statement"]) == 1
    assert policy["policyDocument"]["Statement"][0]["Effect"] == "Allow"
    assert len(policy["policyDocument"]["Statement"][0]["Resource"]) == 2
    assert policy["context"]["userId"] == TEST_USER_ID
    assert policy["context"]["scope"] == "full_access"


def test_lambda_handler_valid_token(mock_environment):
    event = {"authorizationToken": f"Bearer {TEST_TOKEN}", "methodArn": TEST_METHOD_ARN}

    with (
        patch("api_authenticator.handler.get_azure_signing_keys") as mock_get_keys,
        patch("api_authenticator.handler.get_key_for_token") as mock_get_key,
        patch("api_authenticator.handler.jwt.decode") as mock_decode,
    ):
        # Mock the key retrieval
        mock_get_keys.return_value = [MOCK_RSA_KEY]
        mock_get_key.return_value = MOCK_RSA_KEY

        # Mock JWT decode to return valid claims
        mock_decode.return_value = {
            "sub": TEST_USER_ID,
            "exp": (datetime.utcnow() + timedelta(hours=1)).timestamp(),
            "aud": "test_client_id",
        }

        result = lambda_handler(event, {})

        # Verify the result
        assert result["principalId"] == TEST_USER_ID
        assert result["policyDocument"]["Statement"][0]["Effect"] == "Allow"

        # Verify our mocks were called correctly
        mock_get_keys.assert_called_once()
        mock_get_key.assert_called_once_with(TEST_TOKEN, [MOCK_RSA_KEY])
        mock_decode.assert_called_once_with(
            TEST_TOKEN,
            MOCK_RSA_KEY,
            algorithms=["RS256"],
            audience=os.environ.get("AZURE_APP_CLIENT_ID"),
            options={
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )


def test_lambda_handler_invalid_token():
    event = {"authorizationToken": "Invalid", "methodArn": TEST_METHOD_ARN}

    with pytest.raises(Exception) as exc_info:
        lambda_handler(event, {})
    assert str(exc_info.value) == "Unauthorized"


def test_lambda_handler_expired_token(mock_environment, mock_signing_keys):
    event = {"authorizationToken": f"Bearer {TEST_TOKEN}", "methodArn": TEST_METHOD_ARN}

    with (
        patch("api_authenticator.handler.jwt.decode") as mock_decode,
        patch("api_authenticator.handler.jwt.get_unverified_header") as mock_header,
        patch("requests.get") as mock_get,
    ):
        # Mock JWT decode
        mock_decode.return_value = {
            "sub": TEST_USER_ID,
            "exp": (datetime.utcnow() - timedelta(hours=1)).timestamp(),
        }

        # Mock JWT header
        mock_header.return_value = {"kid": TEST_KEY_ID}

        # Mock signing keys response
        mock_response = MagicMock()
        mock_response.json.return_value = {"keys": mock_signing_keys}
        mock_get.return_value = mock_response

        with pytest.raises(Exception) as exc_info:
            lambda_handler(event, {})
        assert str(exc_info.value) == "Unauthorized"
