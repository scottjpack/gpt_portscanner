import argparse
import boto3
import json
from tabulate import tabulate

def invoke_lambda(lambda_client, function_name, payload):
    response = lambda_client.invoke(
        FunctionName=function_name,
        Payload=payload,
    )
    response_payload = response['Payload'].read().decode('utf-8')
    return response_payload

def get_all_scan_results(table_client, dynamodb_table_name, queue_client=None, queue_url=None):
    if queue_client and queue_url:
        response = queue_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['ApproximateNumberOfMessagesNotVisible'])
        num_in_flight = int(response['Attributes']['ApproximateNumberOfMessagesNotVisible'])
        if num_in_flight > 0:
            print(f'Warning: There are {num_in_flight} messages in flight in the SQS queue. Results may be incomplete.')

    response = table_client.scan(TableName=dynamodb_table_name)

    scan_results = []
    for item in response['Items']:
        scan_results.append({
            'id': item['id']['S'],
            'ip_address': item['ip_address']['S'],
            'open_ports': item['open_ports']['NS']
        })

    return scan_results

def get_all_scan_results(table_client, dynamodb_table_name):
    response = table_client.scan(TableName=dynamodb_table_name)
    headers = ['ID', 'IP Address', 'Open Ports']
    data = []
    for item in response['Items']:
        scan_id = item['id']['S']
        ip_address = item['ip_address']['S']
        open_ports = ', '.join(item['open_ports']['NS']) if 'open_ports' in item else '0'
        data.append([scan_id, ip_address, open_ports])
    if not data:
        return 'No scan results found.'

    table = tabulate(data, headers=headers)
    return table

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--stack-name', help='name of the stack', default="PortScannerStack")
    parser.add_argument('--cidr', help='single cidr to scan')
    parser.add_argument('--cidr-file', help='file with newline-separated list of cidrs to scan')
    parser.add_argument('--query-results', action='store_true', help='query scan results for the given cidr(s)')
    parser.add_argument('--get-all-results', action='store_true', help='fetch all existing scan results')
    args = parser.parse_args()

    lambda_client = boto3.client('lambda')
    cfn_client = boto3.client('cloudformation')
    table_client = boto3.client('dynamodb')
    sqs_client = boto3.client('sqs')

    function_name = None
    dynamodb_table_name = None
    queue_url = None
    stack_response = cfn_client.describe_stacks(StackName=args.stack_name)
    for output in stack_response['Stacks'][0]['Outputs']:
        if output['OutputKey'] == 'ScanRequestHandlerFunction':
            function_name = output['OutputValue']
        elif output['OutputKey'] == 'ScanResultsTable':
            dynamodb_table_name = output['OutputValue']
        elif output['OutputKey'] == 'ScanRequestQueue':
            queue_url = output['OutputValue']
        else:
            continue

    if function_name is None:
        print('Error: could not find ScanRequestHandlerFunction output in stack')
        exit(1)

    if args.get_all_results:
        scan_results = get_all_scan_results(table_client, dynamodb_table_name)
        print(scan_results)
        # Check if there are messages in flight
        response = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['ApproximateNumberOfMessagesNotVisible'])
        in_flight_count = int(response['Attributes']['ApproximateNumberOfMessagesNotVisible'])
        if in_flight_count > 0:
            print('\nWARNING: There are {} messages still in flight and results may be incomplete.\n'.format(in_flight_count))
        exit(0)

    if args.query_results:
        if not args.cidr and not args.cidr_file:
            print('Error: must provide either --cidr or --cidr-file')
            exit(1)

        cidr_list = []
        if args.cidr:
            cidr_list.append(args.cidr)
        elif args.cidr_file:
            with open(args.cidr_file, 'r') as f:
                cidr_list = [line.strip() for line in f.readlines()]

        scan_results = get_scan_results(table_client, cidr_list)
        for result in scan_results:
            print('{}\t{}\t{}'.format(result['id'], result['ip_address'], ','.join(result['open_ports'])))
        response = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['ApproximateNumberOfMessagesNotVisible'])
        in_flight_count = int(response['Attributes']['ApproximateNumberOfMessagesNotVisible'])
        if in_flight_count > 0:
            print('\nWARNING: There are {} messages still in flight and results may be incomplete.\n'.format(in_flight_count))

    else:
        if not args.cidr and not args.cidr_file:
            print('Error: must provide either --cidr or --cidr-file')
            exit(1)

        payload = {'cidrs': []}
        if args.cidr:
            payload['cidrs'].append(args.cidr)
        elif args.cidr_file:
            with open(args.cidr_file, 'r') as f:
                payload['cidrs'] = [line.strip() for line in f.readlines()]

        response_payload = invoke_lambda(lambda_client, function_name, str.encode(json.dumps(payload)))
        print(response_payload)

