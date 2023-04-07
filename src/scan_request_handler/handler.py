import uuid
import ipaddress
import json
import logging
import os
import boto3

from typing import List, Dict, Union

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sqs_client = boto3.client('sqs')

class ScanRequest:
    """
    Represents a single scan request.
    """
    def __init__(self, ip_address: str, scan_id: str, initiating_lambda: str):
        self.ip_address = ip_address
        self.scan_id = scan_id
        self.initiating_lambda = initiating_lambda

    def to_dict(self) -> Dict:
        """
        Returns the scan request as a dictionary.

        Returns:
            dict: The scan request as a dictionary.
        """
        return {
            'ip_address': self.ip_address,
            'scan_id': self.scan_id,
            'initiating_lambda': self.initiating_lambda
        }

def is_valid_cidr(cidr: str) -> bool:
    """
    Checks if a string is a valid CIDR notation.

    Args:
        cidr (str): The CIDR notation to validate.

    Returns:
        bool: True if the CIDR is valid, False otherwise.
    """
    try:
        ipaddress.IPv4Network(cidr)
        return True
    except ValueError:
        return False

def split_cidr(cidr: str) -> List[str]:
    """
    Splits a CIDR notation into a list of individual IP addresses.

    Args:
        cidr (str): The CIDR notation to split.

    Returns:
        list: A list of individual IP addresses.
    """
    ip_network = ipaddress.IPv4Network(cidr)
    return [str(ip) for ip in ip_network.hosts()]

def submit_scan_request_batch(ip_addresses: List[str], scan_id: str, initiating_lambda: str) -> Dict:
    """
    Submits a batch of scan requests for a list of IP addresses to the scan request queue.

    Args:
        ip_addresses (list): A list of IP addresses to scan.
        scan_id (str): The unique ID for the scan request batch.
        initiating_lambda (str): The name of the Lambda function that initiated the scan.

    Returns:
        dict: The response from SQS.
    """
    queue_url = os.environ['SCAN_REQUEST_QUEUE_URL']
    entries = []
    for ip_address in ip_addresses:
        scan_request = ScanRequest(ip_address, scan_id, initiating_lambda)
        entry = {
            'Id': str(uuid.uuid4()),
            'MessageBody': json.dumps(scan_request.to_dict())
        }
        entries.append(entry)

    response = sqs_client.send_message_batch(
        QueueUrl=queue_url,
        Entries=entries
    )
    return response

def handler(event: Dict[str, Union[str, List[str]]], context: object) -> Dict[str, Union[int, str]]:
    """
    Handles a scan request by splitting the provided CIDR notations into individual IP addresses
    and submitting a scan request batch for each set of 10 IP addresses to the scan request queue.

    Args:
        event (dict): The event data passed to the function.
        context (object): The context object passed to the function.

    Returns:
        dict: A response indicating the number of scan requests submitted.
    """
    logger.info('Received event: {}'.format(json.dumps(event)))

    # Validate input
    if 'cidrs' not in event:
        return {'error': 'Missing "cidrs" parameter.'}
    if not isinstance(event['cidrs'], list):
        return {'error': 'Invalid type for cidrs'}

    # Generate scan ID
    scan_id = str(uuid.uuid4())

    # Split CIDRs into individual IP addresses and submit in batches of 10
    ip_addresses = []
    for cidr in event['cidrs']:
        ip_addresses.extend(split_cidr(cidr))

    responses = []
    for i in range(0, len(ip_addresses), 10):
        batch_ip_addresses = ip_addresses[i:i+10]
        response = submit_scan_request_batch(batch_ip_addresses, scan_id, os.environ['AWS_LAMBDA_FUNCTION_NAME'])
        responses.append(response)

    return {'submitted': len(ip_addresses), 'batches': len(responses)}

