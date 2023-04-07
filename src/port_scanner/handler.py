import os
import boto3
import json
import socket
import time
import logging
import asyncio

from typing import List

logger = logging.getLogger(__name__)

dynamodb = boto3.client('dynamodb')


COMMON_PORTS: List[int] = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5901, 8080, 8443]


class ScanResult:
    """Class to represent a scan result object."""

    def __init__(self, scan_id: str, ip_address: str, open_ports: List[int], scan_timestamp: int):
        """
        Initialize a ScanResult object.

        Args:
        - scan_id (str): The ID of the scan request.
        - ip_address (str): The IP address that was scanned.
        - open_ports (List[int]): A list of open port numbers.
        - scan_timestamp (int): The epoch timestamp when the scan was performed.
        """
        self.scan_id = scan_id
        self.ip_address = ip_address
        self.open_ports = open_ports
        self.scan_timestamp = scan_timestamp

async def scan_port(ip_address: str, port: int) -> bool:
    """
    Scans a port on an IP address and returns True if the port is open, False otherwise.

    Args:
    - ip_address (str): The IP address to scan.
    - port (int): The port number to scan.

    Returns:
    - True if the port is open, False otherwise.
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip_address, port), timeout=2)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

def scan_ip_address(ip_address: str) -> List[int]:
    """
    Scans common ports on an IP address and returns a list of open ports.

    Args:
    - ip_address (str): The IP address to scan.

    Returns:
    - A list of open port numbers.
    """
    open_ports = []
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    tasks = [scan_port(ip_address, port) for port in COMMON_PORTS]
    results = loop.run_until_complete(asyncio.gather(*tasks))
    for port, result in zip(COMMON_PORTS, results):
        if result:
            open_ports.append(port)
    loop.close()
    return open_ports


def store_scan_result(scan_result: ScanResult) -> None:
    """
    Stores a scan result in DynamoDB.

    Args:
    - scan_result (ScanResult): The ScanResult object to store.
    """
    SCAN_RESULTS_TABLE_NAME = os.environ['SCAN_RESULTS_TABLE_NAME']

    item = {
        'id': {'S': scan_result.scan_id},
        'ip_address': {'S': scan_result.ip_address},
        'scan_timestamp': {'N': str(scan_result.scan_timestamp)}
    }
    if len(scan_result.open_ports) == 0:
        # No open ports detected, report 0 as the only port "open"
        item['open_ports'] = {'NS': ['0']}
    else:
        item['open_ports'] = {'NS': [str(p) for p in scan_result.open_ports]}
    try:
        dynamodb.put_item(TableName=SCAN_RESULTS_TABLE_NAME, Item=item)
    except Exception as e:
        logger.error(f"Error storing scan result for {scan_result.ip_address}: {str(e)}")


def handler(event: dict, context: dict) -> dict:
    """
    Lambda function handler that performs a port scan on an IP address specified in an SQS message.

    Args:
    - event (dict): The Lambda event dictionary.
    - context (dict): The Lambda context dictionary.

    Returns:
    - dict: A dictionary with a 'statusCode' and 'body' key, indicating the status of the function.
    """
    for record in event['Records']:
        try:
            message_body = json.loads(record['body'])
            ip_address: str = message_body['ip_address']
            scan_id: str = message_body['scan_id']
            open_ports = scan_ip_address(ip_address)
            logger.debug(f"Scan result for {ip_address}: {open_ports}")
            timestamp: int = int(time.time())
            scan_result = ScanResult(scan_id, ip_address, open_ports, timestamp)
            store_scan_result(scan_result)

        except Exception as e:
            logger.error(f"Error processing SQS message: {str(e)}")
            return {'statusCode': 500, 'body': 'Error processing SQS message.'}

    return {'statusCode': 200, 'body': 'OK'}
           
