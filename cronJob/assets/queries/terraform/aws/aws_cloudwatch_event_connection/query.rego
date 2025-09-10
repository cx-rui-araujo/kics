package terraform.aws

violation[{"msg": msg, "resource": after.name}] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  after := resource.change.after
  key := after.kms_key_identifier
  startswith(key, "alias/aws/")
  msg := sprintf("CloudWatch Event Connection '%v' uses default AWS-managed KMS key '%v'", [after.name, key])
}