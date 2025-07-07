package main

__rego_metadata__ := {
  "id": "KICS-AWS-CLOUDWATCH-EVENT-BUS-001",
  "title": "aws_cloudwatch_event_bus dead_letter_config must have encryption enabled",
  "severity": "HIGH",
  "type": "terraform"
}

resource_blocks := data.tf.resource_blocks

deny[block] {
  block := resource_blocks[_]
  block.type == "aws_cloudwatch_event_bus"
  dlc := block.block_attributes["dead_letter_config"]
  dlc
  not dlc.encryption_enabled.value == true
}
