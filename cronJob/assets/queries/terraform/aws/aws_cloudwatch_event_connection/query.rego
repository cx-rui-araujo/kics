package terraform.aws_cloudwatch_event_connection_kms_key_identifier

__rego_metadoc__ := {
  "id": "AWS9999",
  "version": "1.0.0",
  "title": "Ensure aws_cloudwatch_event_connection does not use AWS-managed default KMS key",
  "severity": "MEDIUM",
  "description": "Using the default AWS-managed KMS key (alias/aws/*) for CloudWatch Event Connection can lead to insufficient access control. A customer-managed CMK should be used.",
  "queryType": "VULNERABILITY",
  "engineVersion": "2.0"
}

denied[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  after := resource.change.after
  key := after.kms_key_identifier
  startswith(key, "alias/aws/")
  msg := sprintf("Resource '%s' uses AWS-managed default KMS key '%s', use a customer-managed CMK instead", [resource.address, key])
}