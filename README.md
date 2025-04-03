# Custom Lambda Authorizer

This example shows how to use a custom Lambda authorizer to validate a JWT token.
## JWT token structure
a JWT token can be validated at https://jwt.io

```json
{
  "aud": "3bfbad3f-818b-4c5f-9f6a-413e5f16a1d0",
  "iss": "https://b2clogin.com/4a6f6f78-80a9-4c7a-8bfe-6c0a4cb5a6a6/v2.0/",
  "exp": 1743662689,
  "nbf": 1743660889,
  "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
  "extension_CustomerID": "22",
  "name": "Doe, John",
  "extension_GroupID": "3",
  "extension_bps": "22",
  "family_name": "Doe",
  "given_name": "John",
  "emails": [
    "john@acme.com"
  ],
  "tfp": "B2C_1_SmartDMA_Acceptatie_SignIn",
  "nonce": "0195fa49-65d7-722b-bd5e-aa6798721b20",
  "azp": "3bfbad3f-818b-4c5f-9f6a-413e5f16a1d0",
  "ver": "1.0",
  "iat": 1743660889
}
```
Important fields:
| Field | Meaning| Description |
| --- | --- | --- |
| `sub` | Subject | the user id |
| `name` | Name | the user name |
| `iat` | Issued At | the time the token was issued |
| `exp` | Expiration Time | the time the token expires |
| `iss` | Issuer | the issuer of the token |
| `aud` | Audience | the audience of the token |
| `azp` | Authorized Party | the party that authorized the token |
| `tfp` | Tenant Flow Policy | the tenant flow policy |

The JWT token also has a header section
```json
{
  "alg": "RS256",
  "kid": "X5eXk4xyojNFum1kl2Ytv8dlNP4-c57dO6QGTVBwaNk",
  "typ": "JWT"
}
```
Important fields:
| Field | Meaning| Description |
| --- | --- | --- |
| `alg` | Algorithm | the algorithm used to sign the token |
| `kid` | Key ID | the key id used to sign the token |
| `typ` | Type | the type of the token |

## To validate the token:
The key steps to validate a JWT token are:

1. Get the signing keys
2. Get the specific key used to sign this token
3. Validate the token

**Code Snippet example**
```python
from jose import jwt

auth_header = event.get("authorizationToken", "")

# Get the signing keys
signing_keys = get_azure_signing_keys()

# Get the specific key used to sign this token
key = get_key_for_token(token, signing_keys)

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

# Check if token is expired
now = datetime.utcnow().timestamp()
if claims.get("exp", 0) < now:
    raise ValueError("Token is expired")

# Use sub claim for user ID (Azure B2C standard)
user_id = claims.get("sub")
```

### (1) get_azure_signing_keys
The function `get_azure_signing_keys` fetches the signing keys from Azure AD's JWKS endpoint.
It uses lru_cache to cache the keys for 1 minute which helps for performance.

**tenant_id**: The tenant_id for MS B2C is the tenant_id of the Azure AD, and was extracted from the JWT token `azp` claim. See the JWT token structure above.

**policy_name**: The policy name for MS B2C is the name of the policy used for the authentication and was extracted from the JWT token `tfp` claim. See the JWT token structure above.

**jwks_uri**: The JWKS (JSON Web Key Set) endpoint is the endpoint from which the signing keys are fetched. It is constructed using the tenant_id and policy_name. The URL is a standard MS B2C URL found by looking at the [MS B2C documentation](https://learn.microsoft.com/en-us/azure/active-directory-b2c/technical-overview#jwks-endpoint).

**Code Snippet example**
```python
from functools import lru_cache
from jose import jwt

@lru_cache(maxsize=1)
def get_azure_signing_keys():
    tenant_id = os.environ.get("AZURE_TENANT_ID")
    policy_name = os.environ.get("AZURE_POLICY_NAME")

    jwks_uri = f"https://{tenant_id}.b2clogin.com/{tenant_id}.onmicrosoft.com/{policy_name}/discovery/v2.0/keys"
    response = requests.get(jwks_uri)
    response.raise_for_status()
    keys = response.json()["keys"]
    return keys
```

### (2) get_key_for_token
The function `get_key_for_token` fetches the specific key used to sign this token. This finds a matching key in the JWKS (JSON Web Key Set) based on the key id (kid) extracted from the token header. And this validates the jwt token against the signing authority.

**Code Snippet example**
```python
from jose import jwt

def get_key_for_token(token: str, signing_keys: list) -> dict:
    headers = jwt.get_unverified_headers(token)
    key_id = headers.get("kid")

    for key in signing_keys:
        if key["kid"] == key_id:
            return key
```

### (3) Generate Policy
The function `generate_policy` generates a policy document for API Gateway custom authorizer. More detailed info can be found in the [AWS documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html#http-api-lambda-authorizer-policy).

**Code Snippet example**
```python

def generate_policy(principal_id: str, effect: str, resource: str):
    arn_parts = resource.split(":")
    region = arn_parts[3]
    account_id = arn_parts[4]
    api_parts = arn_parts[5].split("/")
    api_id = api_parts[0]
    stage = api_parts[1]

    # Create fully qualified ARN with wildcards
    resource_arn = f"arn:aws:execute-api:{region}:{account_id}:{api_id}/{stage}/*"

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

    return policy
```

# Appendix
When calling the jwks_url endpoint the results are below.

**Response sample**
```json
{
    "keys": [
        {
            "kid": "X5eXk4xyojNFum1kl2Ytv8dlNP4-c57dO6QGTVBwaNk",
            "nbf": 1493763266,
            "use": "sig",
            "kty": "RSA",
            "e": "AQAB",
            "n": "mF_3oqmn2KlprwWVlqnz6Gn6Qj4qZJ3BOqTtZ6F6n6Q5qZJ3BOqTtZ6F6n6Q5qZJ3BOqTtZ6F6n6Q5qZJ3BOqTtZ6F6n6Q5qZJ3BOqTtZ6F6n6Q5qZJ3BOqTtZ6F6n6Q5qZJ3BOqTtZ6F6n6Q5qZJ3"
        }
    ]
}
```