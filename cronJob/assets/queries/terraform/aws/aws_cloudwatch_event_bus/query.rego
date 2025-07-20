package tfsec.aws.CloudWatchEventBus.DLQCheck

__rego_metadata__ = {
  \"id\": \"AWS.CF.EB.DLQ.1\",
  \"title\": \"Ensure CloudWatch Event Bus dead_letter_config uses encrypted SQS queue\",
  \"severity\": \"HIGH\",
  \"provider\": \"aws\",
  \"service\": \"cloudwatch_event_bus\",
  \"resource\": \"aws_cloudwatch_event_bus\"
}

deny[message] {
  tfplan := data.terraform.tfplan
  resource := tfplan.resource_changes[_]
  resource.type == \"aws_cloudwatch_event_bus\"
  after := resource.change.after
  after.dead_letter_config != null
  dlq := after.dead_letter_config[0]
  not dlq.kms_key_arn
  message := sprintf(\"Resource '%s' dead_letter_config must include kms_key_arn for encryption\", [resource.address])
}
