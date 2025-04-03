import os
from datetime import datetime
from functools import lru_cache
from typing import Any, Dict

import requests
from jose import jwt


@lru_cache(maxsize=1)
def get_azure_signing_keys():
    """
    Get the signing keys from Azure AD's JWKS endpoint.
    Cached to avoid frequent HTTP requests.
    """
    try:
        # Use tenant-specific endpoint
        tenant_id = os.environ.get("AZURE_TENANT_ID")
        policy_name = os.environ.get("AZURE_POLICY_NAME")

        # Azure AD B2C JWKS endpoint format
        jwks_uri = f"https://{tenant_id}.b2clogin.com/{tenant_id}.onmicrosoft.com/{policy_name}/discovery/v2.0/keys"

        # print(f"Fetching keys from: {jwks_uri}")
        response = requests.get(jwks_uri)
        response.raise_for_status()
        keys = response.json()["keys"]
        # print(f"Retrieved keys: {json.dumps(keys)}")
        return keys
    except Exception as e:
        print(f"Error fetching signing keys: {str(e)}")
        return None


def get_key_for_token(token: str, signing_keys: list) -> dict:
    """Get the correct signing key for the token."""
    try:
        headers = jwt.get_unverified_headers(token)
        key_id = headers.get("kid")
        if not key_id:
            raise ValueError("No 'kid' in token header")

        # print(f"Looking for key with kid: {key_id}")
        # print(f"Available keys: {json.dumps(signing_keys)}")

        # Find the matching key in the JWKS
        for key in signing_keys:
            if key["kid"] == key_id:
                return key

        raise ValueError(f"No matching key found for kid: {key_id}")
    except Exception as e:
        print(f"Error getting key: {str(e)}")
        raise


def generate_policy(principal_id: str, effect: str, resource: str):
    """Generate an IAM policy document for API Gateway custom authorizer."""
    print(f"Incoming resource ARN: {resource}")

    # Parse the resource ARN components
    arn_parts = resource.split(":")
    region = arn_parts[3]
    account_id = arn_parts[4]
    api_parts = arn_parts[5].split("/")
    api_id = api_parts[0]
    stage = api_parts[1]

    # Create fully qualified ARN with wildcards
    resource_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}/{stage}/*"

    # print(f"Generated resource ARN: {resource_arn}")
    # print(f"Principal ID: {principal_id}")
    # print(f"Effect: {effect}")

    policy = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": [
                        resource_arn,
                        resource,
                    ],
                }
            ],
        },
        "context": {"userId": principal_id, "scope": "full_access"},
    }

    # print(f"Generated policy: {json.dumps(policy, indent=2)}")
    return policy


def lambda_handler(event: Dict[str, Any], context: Any):
    """
    Custom authorizer for API Gateway that validates Azure AD JWT tokens.
    """
    print("=== Starting token validation ===")
    # print(f"Event: {json.dumps(event, indent=2)}")

    try:
        # Get the Authorization token from the header
        auth_header = event.get("authorizationToken", "")
        if not auth_header.startswith("Bearer "):
            raise ValueError("Authorization header must start with 'Bearer'")

        token = auth_header[7:]  # Remove 'Bearer ' prefix
        print("Token extracted successfully")

        # Get the signing keys
        signing_keys = get_azure_signing_keys()
        if not signing_keys:
            raise ValueError("Unable to fetch signing keys")

        # Get the specific key used to sign this token
        key = get_key_for_token(token, signing_keys)
        if not key:
            raise ValueError("Unable to find appropriate signing key")

        # Validate the token
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=os.environ.get("AZURE_APP_CLIENT_ID"),
            options={
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )

        # print(f"Token claims: {json.dumps(claims, indent=2)}")

        # Check if token is expired
        now = datetime.utcnow().timestamp()
        if claims.get("exp", 0) < now:
            raise ValueError("Token is expired")

        # Use sub claim for user ID (Azure B2C standard)
        user_id = claims.get("sub")
        if not user_id:
            raise ValueError("No user ID (sub) in token claims")

        # Generate policy
        return generate_policy(user_id, "Allow", event["methodArn"])

    except Exception as e:
        print(f"Error: {str(e)}")
        raise Exception("Unauthorized")
