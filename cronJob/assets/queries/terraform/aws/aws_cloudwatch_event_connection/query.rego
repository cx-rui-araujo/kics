package terraform.kms

__rego_metadata__ := {
  "id": "KICS-EXAMPLE-1",
  "title": "Ensure aws_cloudwatch_event_connection kms_key_identifier uses a whitelisted KMS key",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  after := resource.change.after
  key := after.kms_key_identifier
  not startswith(key, "arn:aws:kms:us-east-1:123456789012:key/")
  msg := sprintf("aws_cloudwatch_event_connection '%s' uses non-whitelisted kms_key_identifier: %s", [resource.address, key])
}