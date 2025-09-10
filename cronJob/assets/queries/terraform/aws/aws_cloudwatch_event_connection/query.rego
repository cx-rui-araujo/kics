package terraform.aws.CloudWatchEventConnection

__rego_metadata__ := {
  "id": "AWS999",
  "title": "Avoid cross-account KMS keys for AWS CloudWatch Event Connection",
  "severity": "MEDIUM",
  "type": "Misconfiguration"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  identifier := resource.change.after.kms_key_identifier
  startswith(identifier, "arn:aws:kms:")
  msg := sprintf("CloudWatch Event Connection uses cross-account KMS key identifier %s", [identifier])
}