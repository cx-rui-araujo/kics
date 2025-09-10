package kics.tf.cloudwatch_event_connection

import data.tfplan

violation[issue] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  kms := resource.change.after.kms_key_identifier
  startswith(kms, "arn:aws:kms")
  contains(kms, "/alias/aws/")
  issue := {"message": sprintf("Using default AWS-managed KMS key in aws_cloudwatch_event_connection: %v", [kms]), "resource": resource.address}
}