AWS_REGION ?= us-east-1
S3_BUCKET ?= buckety-bucketface
STACK_NAME ?= PortScannerStack

TEMPLATE_FILE := template.yaml
PACKAGED_TEMPLATE_FILE := packaged.yaml

.PHONY: deploy
deploy: package deploy-stack


.PHONY: package
package:
	sam package \
		--template-file $(TEMPLATE_FILE) \
		--output-template-file $(PACKAGED_TEMPLATE_FILE) \
		--s3-bucket $(S3_BUCKET)

.PHONY: deploy-stack
deploy-stack:
	sam deploy \
		--template-file $(PACKAGED_TEMPLATE_FILE) \
		--stack-name $(STACK_NAME) \
		--capabilities CAPABILITY_IAM \
		--region $(AWS_REGION)

.PHONY: test
test:
	pytest