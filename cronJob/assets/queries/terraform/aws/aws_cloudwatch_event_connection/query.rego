package terraform.aws.cloudwatch_event_connection

__rego_metadata__ = {"id": "AWS004", "title": "AWS CloudWatch Event Connection should not use AWS-managed KMS key", "severity": "MEDIUM", "type": "VULNERABILITY", "category": "Encryption"}

violation[{"msg": msg, "resource": resource.address}] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  kms := resource.change.after.kms_key_identifier
  startswith(kms, "alias/aws/")
  msg := sprintf("Connection %s uses default AWS-managed KMS key %s, consider using a customer-managed key.", [resource.address, kms])
}