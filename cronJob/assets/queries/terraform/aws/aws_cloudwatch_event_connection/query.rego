package terraform.aws.cloudwatch_event_connection

__rego_metadata__ = {
  "id": "KICS-AWS-9999",
  "title": "Ensure kms_key_identifier uses a valid KMS key ARN",
  "severity": "HIGH",
  "type": "terraform"
}

deny[issue] {
  resource := tfplan.resource_changes.aws_cloudwatch_event_connection[_]
  after := resource.change.after
  key := after.kms_key_identifier
  key != ""
  not startswith(key, "arn:aws:kms:")
  issue = sprintf("aws_cloudwatch_event_connection '%s' uses an invalid kms_key_identifier '%s'", [resource.address, key])
}