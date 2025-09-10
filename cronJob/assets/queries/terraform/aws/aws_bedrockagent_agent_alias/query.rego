package main

import data.terraform as tf

__rego_metadata__ := {
  "id": "AWS999",
  "title": "Bedrock agent alias missing routing_configuration",
  "severity": "HIGH",
  "type": "misconfiguration",
  "platform": "terraform"
}

denied[resp] {
  resource := tf.resources[resource_idx]
  resource.type == "aws_bedrockagent_agent_alias"
  not resource.values.routing_configuration
  resp := {
    "resource_id": resource.id,
    "message": "Missing explicit routing_configuration may result in unintended alias routing"
  }
}