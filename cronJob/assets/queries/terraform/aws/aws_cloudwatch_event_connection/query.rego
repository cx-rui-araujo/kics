package terraform.aws

import data.terraform.tfplan as tfplan

violation[{
  "msg": msg,
  "resource": resource.address,
}] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  values := resource.change.after
  # Detect use of default AWS-managed KMS key
  values.kms_key_identifier == "alias/aws/events"
  msg := "CloudWatch Event Connection uses the default AWS-managed KMS key which may not meet your security requirements."
}