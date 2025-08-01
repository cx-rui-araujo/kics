package kics

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  kms := resource.change.after.kms_key_identifier
  (kms == "" or startswith(kms, "alias/aws/"))
  msg := sprintf("Connection '%s' uses default AWS-managed KMS key, please use a customer-managed KMS key", [resource.address])
}