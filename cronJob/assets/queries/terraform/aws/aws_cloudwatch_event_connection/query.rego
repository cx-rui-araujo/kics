package terraform.aws.kms

# Detect use of AWS-managed KMS keys in CloudWatch Event Connections
violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  after := resource.change.after
  after.kms_key_identifier != ""
  contains(after.kms_key_identifier, "alias/aws")
}