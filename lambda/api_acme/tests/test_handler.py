import pytest

from api_slimmewatermeter.handler import app, lambda_handler

# Test data
TEST_USER_ID = "8fcbad96-7b5d-4a15-80f1-55a3ba7b6f6f"
TEST_USER_DATA = {
    "userId": TEST_USER_ID,
    "housingType": "Rijtjeshuis",
    "household": "4 personen",
}


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_get_user_data_success(client, mock_environment, mock_dynamodb):
    # mock dymandodb response for item
    mock_dynamodb.get_item.return_value = {"Item": TEST_USER_DATA}

    response = client.get(f"/getUserData/{TEST_USER_ID}")

    assert response.status_code == 200
    assert response.json == TEST_USER_DATA

    mock_dynamodb.get_item.assert_called_once_with(Key={"userId": TEST_USER_ID})

    # Verify CORS headers
    assert response.headers.get("Access-Control-Allow-Origin") == "*"
    assert "POST, OPTIONS" in response.headers.get("Access-Control-Allow-Methods")
    assert "Content-Type, Authorization" in response.headers.get(
        "Access-Control-Allow-Headers"
    )


def test_get_user_data_not_found(client, mock_environment, mock_dynamodb):
    # mock dymandodb response for item
    mock_dynamodb.get_item.return_value = {"Item": None}

    response = client.get(f"/getUserData/{TEST_USER_ID}")

    assert response.status_code == 200
    assert response.json is None


def test_get_user_data_error(client, mock_environment, mock_dynamodb):
    # mock dymandodb response for item
    mock_dynamodb.get_item.side_effect = Exception("DynamoDB error")

    response = client.get(f"/getUserData/{TEST_USER_ID}")

    assert response.status_code == 500
    assert response.json["message"] == "Error retrieving from DynamoDB"
    assert response.json["error"] == "DynamoDB error"


def test_post_user_data_success(client, mock_environment, mock_dynamodb):
    # mock dymandodb response for item
    mock_dynamodb.put_item.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    response = client.post(
        "/postUserData", json=TEST_USER_DATA, content_type="application/json"
    )

    assert response.status_code == 200
    assert response.json["status"] == "success"
    assert response.json["message"] == "Data saved successfully"

    mock_dynamodb.put_item.assert_called_once_with(Item=TEST_USER_DATA)

    # Verify CORS headers
    assert response.headers.get("Access-Control-Allow-Origin") == "*"
    assert "POST, OPTIONS" in response.headers.get("Access-Control-Allow-Methods")
    assert "Content-Type, Authorization" in response.headers.get(
        "Access-Control-Allow-Headers"
    )


def test_put_user_data_success(client, mock_environment, mock_dynamodb):
    # mock dymandodb response for item
    mock_dynamodb.put_item.return_value = {
        "message": "Data saved successfully",
        "status": "success",
    }

    response = client.put(
        "/postUserData", json=TEST_USER_DATA, content_type="application/json"
    )

    assert response.status_code == 200
    assert response.json["status"] == "success"
    assert response.json["message"] == "Data saved successfully"

    mock_dynamodb.put_item.assert_called_once_with(Item=TEST_USER_DATA)


def test_post_user_data_error(client, mock_environment, mock_dynamodb):
    # mock dymandodb response for item
    mock_dynamodb.put_item.side_effect = Exception("DynamoDB error")

    response = client.post(
        "/postUserData", json=TEST_USER_DATA, content_type="application/json"
    )

    assert response.status_code == 500
    assert response.json["message"] == "Error posting to DynamoDB"
    assert response.json["error"] == "DynamoDB error"


def test_lambda_handler(mock_environment, mock_dynamodb):
    # mock API Gateway event
    event = {
        "httpMethod": "GET",
        "path": f"/getUserData/{TEST_USER_ID}",
        "headers": {},
        "queryStringParameters": None,
        "pathParameters": {"user_id": TEST_USER_ID},
        "body": None,
    }

    # mock dymandodb response for item
    mock_dynamodb.get_item.return_value = {"Item": TEST_USER_DATA}

    response = lambda_handler(event, {})

    assert int(response["statusCode"]) == 200
    assert "body" in response
    assert "headers" in response

    # Verify CORS headers in response
    headers = response["headers"]
    assert headers.get("Access-Control-Allow-Origin") == "*"
    assert "POST, OPTIONS" in headers.get("Access-Control-Allow-Methods")
    assert "Content-Type, Authorization" in headers.get("Access-Control-Allow-Headers")
