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

To use the port scanner via direct Lambda invocation, follow these steps:

1. Invoke the scan request Lambda function by running the following command:

aws lambda invoke --function-name ScanRequestHandlerFunction --payload file://exampleinvocation.json response.json


Replace `scan_request.json` with a JSON file containing a list of IP addresses or CIDR blocks to scan.

Example:
```
{
  "cidrs": ["10.0.0.0/24", "192.168.1.0/24"]
}
```

2. The scan request function will split the list of addresses into individual scan requests and submit them to the SQS queue.
3. The port scanner function will process the scan requests from the SQS queue, and perform a port scan on each IP address.
4. The results of the port scan will be stored in the DynamoDB table.

Please be aware that scanning large numbers of IP addresses may trigger intrusion detection systems and other security measures. Always obtain proper authorization before performing port scans.

## CLI Tool

The CLI tool allows you to query the scan results stored in DynamoDB or to invoke the Lambda function for a given set of CIDR blocks. The tool requires the AWS CLI credentials to be set up in your environment.

### Installation:
Install Python 3.8 or later.
Run pip install -r requirements.txt to install the dependencies.

```
usage: invoker.py [-h] [--cidr CIDR] [--cidr-file CIDR_FILE] [--query-results] [--get-all-results] [--invoke] [--queue-warning]

optional arguments:
  -h, --help            show this help message and exit
  --stack-name STACK_NAME
                        name of the stack (If not default PortScannerStack)
  --cidr CIDR           single cidr to scan
  --cidr-file CIDR_FILE
                        file with newline-separated list of cidrs to scan
  --query-results       query scan results for the given cidr(s)
  --get-all-results     get all scan results
  --invoke              invoke the function for the given cidr(s)
  --queue-warning       warn if SQS queue has messages in flight
```

### Getting all scan results:
The --get-all-results flag allows you to get all the scan results stored in DynamoDB:
```
./invoker.py --stack-name <stack-name> --get-all-results
```


### Querying scan results:
The --query-results flag allows you to query the scan results for the given CIDR(s):
```
./invoker.py --stack-name <stack-name> --cidr <cidr> --query-results
./invoker.py --stack-name <stack-name> --cidr-file <cidr-file> --query-results
```

### Invoking the function:
The --invoke flag allows you to invoke the Lambda function for the given CIDR(s):
```
./invoker.py --stack-name <stack-name> --cidr <cidr> --invoke
./invoker.py --stack-name <stack-name> --cidr-file <cidr-file> --invoke
```


## Contributing

If you find a bug or have an idea for a new feature, please create an issue on this repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## GPT Chat Histories:
https://sharegpt.com/c/X1GZoHN - Main Thread
https://sharegpt.com/c/0QZBQSo - Unit Test creation thread
