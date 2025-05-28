package main

deny[msg] {
  resource := input.Blocks[_]
  resource.Type == "resource"
  resource.Labels[0] == "aws_cloudwatch_event_connection"
  not resource.HasChild("kms_key_identifier")
  msg := sprintf("Resource '%s' does not define a custom KMS key for encryption.", [resource.Labels[1]])
}