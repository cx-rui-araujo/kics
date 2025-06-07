package kics

import data.terraform.plan as plan

deny[message] {
  plan.resource_changes[_] == rc
  rc.type == "aws_cloudwatch_event_connection"
  not rc.change.after.kms_key_identifier
  message := sprintf("Resource '%s' missing kms_key_identifier for encryption", [rc.address])
}