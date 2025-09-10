package aws.cloudwatch.eventbus

__rego_meta__ := {
  "id": "KICS-AWS-999",
  "title": "Ensure CloudWatch Event Bus Dead Letter Config ARN does not use wildcards",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

violation[{"msg": msg, "resource": address}] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  address := resource.address
  dlc := resource.change.after.dead_letter_config
  dlc != null
  contains(dlc.arn, "*")
  msg := sprintf("Resource %s uses wildcard in dead_letter_config ARN, which may lead to unintended queue usage", [address])
}