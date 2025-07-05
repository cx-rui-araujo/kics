package terraform.aws_cloudwatch_event_connection

violation[{
  "msg": msg,
  "resource": resource.address
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  after := resource.change.after
  after.kms_key_identifier
  startswith(after.kms_key_identifier, "alias/aws/")
  msg := sprintf("Insecure usage of AWS-managed KMS key identifier '%s' for CloudWatch Event Connection. Use a customer-managed key with proper rotation and policy.", [after.kms_key_identifier])
}