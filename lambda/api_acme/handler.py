import os
import logging
import awsgi2
import boto3
from flask import Flask, jsonify, request

app = Flask(__name__)

dynamo_table_name = os.environ.get("DYNAMO_TABLE_NAME")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_table():
    """
    Get DynamoDB table resource.
    """
    dynamodb = boto3.resource("dynamodb")
    return dynamodb.Table(dynamo_table_name)


def verify_user_id(requested_user_id=None):
    """
    Verify that the requested user_id matches the authenticated user_id from the JWT token.
    """
    logger.info(f"Verifying user_id: {requested_user_id}")

    if not requested_user_id or requested_user_id is None:
        logger.error("Missing userId in request data")
        return False

    auth_context = (
        request.environ.get("awsgi.event", {})
        .get("requestContext", {})
        .get("authorizer", {})
    )
    authenticated_user_id = auth_context.get("userId")

    # If no authenticated user_id is found, deny access
    if not authenticated_user_id:
        logger.error("No authenticated user_id found in request context")
        return False

    # Check if the requested user_id matches the authenticated user_id
    is_authorized = authenticated_user_id == requested_user_id

    if not is_authorized:
        logger.error(
            f"User ID mismatch: Authenticated user {authenticated_user_id} tried to access data for user {requested_user_id}"
        )

    return is_authorized


@app.route("/getUserData/<user_id>", methods=["GET"])
def get_user_data_by_id(user_id):
    """
    Retrieves a single entry from the DynamoDB table.
    """
    logger.info(f"Received GET request for user_id: {user_id}")

    # Verify the user_id matches the authenticated user
    if not verify_user_id(user_id):
        response = jsonify(
            status=403, message="Unauthorized: Cannot access unauthorized user data"
        )
        response = add_cors_headers(response)
        return response, 403

    try:
        table = get_table()
        response = table.get_item(Key={"userId": user_id})
        item = response.get("Item")
        logger.info(f"Retrieved item: {item}")
        if not item:
            response = jsonify(None)
        else:
            response = jsonify(item)
        response = add_cors_headers(response)
        return response
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        response = jsonify(
            status=500, message="Error retrieving from DynamoDB", error=str(e)
        )
        response = add_cors_headers(response)
        return response, 500


@app.route("/postUserData", methods=["POST", "PUT"])
def post_user_data():
    """
    Posts a new entry to the DynamoDB table.
    """
    logger.info(f"Method received is: {request.method}")
    try:
        data = request.json

        # Extract the user_id from the request data
        user_id = data.get("userId")

        # Verify the user_id matches the authenticated user
        if not verify_user_id(user_id):
            response = jsonify(
                status=403, message="Unauthorized: Cannot access unauthorized user data"
            )
            response = add_cors_headers(response)
            return response, 403

        table = get_table()
        response = table.put_item(Item=data)

        response = jsonify({"status": "success", "message": "Data saved successfully"})
        response = add_cors_headers(response)
        return response
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        response = jsonify(
            status=500, message="Error posting to DynamoDB", error=str(e)
        )
        response = add_cors_headers(response)
        return response, 500


def add_cors_headers(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
    return response


def lambda_handler(event, context):
    return awsgi2.response(app, event, context)
