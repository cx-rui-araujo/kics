package main

__rego_metadata__ := {
  "id": "AWS_GENERIC_1000",
  "title": "Ensure dead_letter_config specifies CMK encryption",
  "severity": "HIGH",
  "type": "Terraform",
  "category": "Security"
}

deny[{"msg": msg, "resource": resource_name}] {
  resource := input.resource[_]
  resource.type == "aws_cloudwatch_event_bus"
  dead := resource.body.dead_letter_config
  dead
  not dead["kms_key_arn"]
  resource_name := resource.name
  msg := sprintf("Resource '%s' defines a dead_letter_config without KMS encryption", [resource.name])
}