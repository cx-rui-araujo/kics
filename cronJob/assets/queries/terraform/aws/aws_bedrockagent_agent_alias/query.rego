package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_bedrockagent_agent_alias"
  resource.change.after.routing_configuration == null
  msg := sprintf("Resource %s is missing explicit routing_configuration, which may lead to unintended alias routing and versioning issues.", [resource.address])
}