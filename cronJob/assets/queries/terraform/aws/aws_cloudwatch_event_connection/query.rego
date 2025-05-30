package terraform.aws

__rego_metadata__ = {
  "id": "AWS42385",
  "title": "Ensure CloudWatch Event Connection is encrypted with customer managed KMS key",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "description": "CloudWatch Event Connection resources should specify a kms_key_identifier for encryption to prevent unauthorized access to event data.",
  "reference_id": "AWS-42385"
}

violation[resource] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  not resource.change.after.kms_key_identifier
}