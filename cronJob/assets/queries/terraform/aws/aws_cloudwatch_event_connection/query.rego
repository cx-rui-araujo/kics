package terraform.aws_cloudwatch_event_connection

__rego_metadata__ := {
  "id": "AWS999",
  "title": "AWS CloudWatch Event Connection should not use default KMS key",
  "severity": "MEDIUM",
  "type": "KICS",
  "category": "Encryption",
}

deny[msg] {
  resource := input.resource.blocks[_]
  resource.type == "aws_cloudwatch_event_connection"
  kms := resource.attributes.kms_key_identifier
  kms == "alias/aws/kms"
  msg := sprintf("Resource '%s' uses default KMS key '%s', a customer-managed key is recommended.", [resource.labels[0], kms])
}