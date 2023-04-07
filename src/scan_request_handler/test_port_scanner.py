import os
import json
import pytest
import boto3
from moto import mock_sqs, mock_dynamodb2


@pytest.fixture(scope='module')
def test_event():
    return {
        'cidrs': ['192.168.0.0/24']
    }


@mock_sqs
def test_missing_cidrs():
    from scan_request_handler.handler import handler
    # Test with missing 'cidrs' parameter
    from boto3 import client
    sqs_client = client('sqs', region_name='us-east-1')
    queue_url = sqs_client.create_queue(QueueName='test_queue')['QueueUrl']
    os.environ['SCAN_REQUEST_QUEUE_URL'] = queue_url
    os.environ['AWS_LAMBDA_FUNCTION_NAME'] = 'test_function'
    os.environ['AWS_ACCESS_KEY_ID'] = 'dummy_access_key'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'dummy_secret_key'
    os.environ['AWS_SESSION_TOKEN'] = 'dummy_session_token'
    event = {}
    response = handler(event, None)
    assert response == {'error': 'Missing "cidrs" parameter.'}


@mock_sqs
def test_invalid_cidrs():
    from scan_request_handler.handler import handler
    # Test with invalid 'cidrs' parameter'
    from boto3 import client
    sqs_client = client('sqs', region_name='us-east-1')
    queue_url = sqs_client.create_queue(QueueName='test_queue')['QueueUrl']
    os.environ['SCAN_REQUEST_QUEUE_URL'] = queue_url
    os.environ['AWS_LAMBDA_FUNCTION_NAME'] = 'test_function'
    os.environ['AWS_ACCESS_KEY_ID'] = 'dummy_access_key'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'dummy_secret_key'
    os.environ['AWS_SESSION_TOKEN'] = 'dummy_session_token'
    event = {'cidrs': 'not a list'}
    response = handler(event, None)
    assert response == {'error': 'Invalid type for cidrs'}


@mock_sqs
def test_empty_cidrs():
    from scan_request_handler.handler import handler
    # Test with empty 'cidrs' parameter'
    from boto3 import client
    sqs_client = client('sqs', region_name='us-east-1')
    queue_url = sqs_client.create_queue(QueueName='test_queue')['QueueUrl']
    os.environ['SCAN_REQUEST_QUEUE_URL'] = queue_url
    os.environ['AWS_LAMBDA_FUNCTION_NAME'] = 'test_function'
    os.environ['AWS_ACCESS_KEY_ID'] = 'dummy_access_key'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'dummy_secret_key'
    os.environ['AWS_SESSION_TOKEN'] = 'dummy_session_token'
    event = {'cidrs': []}
    response = handler(event, None)
    assert response == {'submitted': 0, 'batches': 0}


@mock_sqs
def test_valid_cidrs():
    from scan_request_handler.handler import handler
    # Test with valid 'cidrs' parameter'
    from boto3 import client
    sqs_client = client('sqs', region_name='us-east-1')
    queue_url = sqs_client.create_queue(QueueName='test_queue')['QueueUrl']
    os.environ['SCAN_REQUEST_QUEUE_URL'] = queue_url
    os.environ['AWS_LAMBDA_FUNCTION_NAME'] = 'test_function'
    os.environ['AWS_ACCESS_KEY_ID'] = 'dummy_access_key'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'dummy_secret_key'
    os.environ['AWS_SESSION_TOKEN'] = 'dummy_session_token'
    event = {'cidrs': ['192.168.0.0/24', '192.168.1.0/24']}
    response = handler(event, None)
    assert response == {'submitted': 508, 'batches': 51}

@mock_dynamodb2
def test_store_scan_result():
    from port_scanner.handler import handler, ScanResult, store_scan_result
    # Assign the table name to the environment variable
    os.environ['SCAN_RESULTS_TABLE_NAME'] = 'test_scan_results'

    # Create a mock DynamoDB table
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table_name = os.environ['SCAN_RESULTS_TABLE_NAME']
    table = dynamodb.create_table(
        TableName=table_name,
        KeySchema=[
            {
                'AttributeName': 'id',
                'KeyType': 'HASH'
            }
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'id',
                'AttributeType': 'S'
            }
        ],
        BillingMode='PAY_PER_REQUEST'
    )

    # Create a test ScanResult object
    scan_result = ScanResult(
        scan_id='test_scan_id',
        ip_address='192.168.0.1',
        open_ports=[22, 80, 443],
        scan_timestamp=1623192000
    )

    # Store the scan result in DynamoDB
    store_scan_result(scan_result)

    # Verify that the scan result was stored correctly
    response = table.get_item(Key={'id': 'test_scan_id'})
    assert 'Item' in response
    assert response['Item']['id'] == 'test_scan_id'
    assert response['Item']['ip_address'] == '192.168.0.1'
    assert response['Item']['scan_timestamp'] == 1623192000
    assert set(int(port) for port in response['Item']['open_ports']) == {22, 80, 443}

    # Clean up the mock DynamoDB table
    table.delete()

    # Remove the environment variable after the test
    os.environ.pop('SCAN_RESULTS_TABLE_NAME')