package terraform.aws.Security

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  key := resource.change.after.kms_key_identifier
  startswith(key, "alias/aws/")
  msg := sprintf("Resource %s uses AWS-managed KMS key %s", [resource.address, key])
}