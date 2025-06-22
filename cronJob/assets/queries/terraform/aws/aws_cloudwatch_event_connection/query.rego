package aws

__rego_metadata__ := { "id": "KICS-aws-42385-1", "title": "Avoid AWS managed KMS keys in CloudWatch Event Connection", "severity": "MEDIUM", "description": "Using AWS managed KMS keys (alias/aws/*) may lack proper controls and rotation.", "resource_kind": "aws_cloudwatch_event_connection" }

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  after := resource.change.after
  key := after.kms_key_identifier
  startswith(key, "alias/aws/")
  msg := sprintf("Resource '%s' is using AWS managed KMS key '%s'", [after.name, key])
}