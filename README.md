# AWS Lambda Port Scanner

This repository contains the source code for an AWS Lambda function that can perform a port scan on a list of IP addresses or CIDR blocks.

## Architecture

The port scanner is built using the following AWS managed services:

- AWS Lambda for compute
- Amazon SQS for scan request queueing
- Amazon DynamoDB for reporting

## Getting Started

To deploy the port scanner, follow these steps:

1. Install the AWS SAM CLI.
2. Clone this repository to your local machine.
3. Deploy the application using the following command:
	make deploy


This will package and deploy the application to your AWS account using AWS CloudFormation and the SAM CLI.

## Usage

To use the port scanner, follow these steps:

1. Invoke the scan request Lambda function by running the following command:

aws lambda invoke --function-name ScanRequestHandlerFunction --payload file://exampleinvocation.json response.json


Replace `scan_request.json` with a JSON file containing a list of IP addresses or CIDR blocks to scan.
2. The scan request function will split the list of addresses into individual scan requests and submit them to the SQS queue.
3. The port scanner function will process the scan requests from the SQS queue, and perform a port scan on each IP address.
4. The results of the port scan will be stored in the DynamoDB table.

Please be aware that scanning large numbers of IP addresses may trigger intrusion detection systems and other security measures. Always obtain proper authorization before performing port scans.

## Configuration

The following environment variables are used to configure the port scanner:

- `SCAN_REQUEST_QUEUE_URL`: The URL of the SQS queue where scan requests are submitted.
- `SCAN_RESULTS_TABLE_NAME`: The name of the DynamoDB table where scan results are stored.

## Contributing

If you find a bug or have an idea for a new feature, please create an issue on this repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
