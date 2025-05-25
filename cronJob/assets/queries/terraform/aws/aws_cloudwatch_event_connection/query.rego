package terraform.aws

metadata = {
  "id": "AWS_CLOUDWATCH_EVENT_CONNECTION_KMS_1",
  "version": "1.0.0",
  "name": "cloudwatch-event-connection-customer-managed-kms",
  "severity": "MEDIUM",
  "type": "terraform",
  "short_description": "CloudWatch Event Connection should use a customer-managed KMS key",
  "description": "Using an AWS-managed KMS key for CloudWatch Event Connection encryption reduces control and auditability. Define a customer-managed KMS key.",
  "category": "Encryption",
  "reference_id": "AWS.CI.KMS.001",
  "urls": ["https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-encryption.html"]
}

deny[msg] {
  resource := tfplan.resource_changes[type == "aws_cloudwatch_event_connection"]
  after := resource.change.after
  kms := after.kms_key_identifier
  kms != ""
  startswith(kms, "alias/aws/")
  msg := sprintf("Resource '%s' uses AWS managed KMS alias '%s', use a customer-managed KMS key instead", [resource.address, kms])
}
