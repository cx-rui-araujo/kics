package terraform.aws_cloudwatch_event_connection

__rego_metadata__ := {
  "id": "AWS999",
  "title": "CloudWatch Event Connection should not use default KMS key",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
  "related_resources": ["aws_cloudwatch_event_connection"]
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  after := resource.change.after
  kms := after.kms_key_identifier
  # Imaginary vulnerability: using AWS default KMS key alias
  startswith(kms, "alias/aws/")
  msg := sprintf("Resource '%s' uses default KMS key '%s', which may expose sensitive connection data", [resource.address, kms])
}