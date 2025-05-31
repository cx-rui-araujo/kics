package terraform.kics
import data.terraform.plan

deny[message] {
  resource := terraform.plan.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  dead := resource.change.after.dead_letter_config
  dead != null
  not is_valid_sqs_arn(dead.arn)
  message := sprintf("Invalid dead_letter_config ARN for resource '%s': %s", [resource.address, dead.arn])
}

is_valid_sqs_arn[arn] {
  re_match("^arn:aws:sqs:[a-z0-9-]+:[0-9]+:[A-Za-z0-9_-]+$", arn)
}