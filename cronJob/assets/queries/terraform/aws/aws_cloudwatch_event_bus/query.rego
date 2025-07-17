package terraform.aws.cloudwatch_event_bus

import data.tfconfig

__rego_metadoc__ := {
  "id": "AWS_DLE_001",
  "version": "1.0",
  "title": "AWS CloudWatch Event Bus missing dead_letter_config",
  "severity": "MEDIUM",
  "description": "Ensure aws_cloudwatch_event_bus resources define a dead_letter_config to prevent event loss."
}

deny[resource] {
  resource := tfconfig.resource["aws_cloudwatch_event_bus"][name]
  not resource.block.block_types.dead_letter_config
}
