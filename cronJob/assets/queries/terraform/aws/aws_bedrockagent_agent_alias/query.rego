package kics

# Warn when aws_bedrockagent_agent_alias is missing explicit routing_configuration
violation[{"resource": resource.address, "msg": "aws_bedrockagent_agent_alias missing explicit routing_configuration, may drop existing routing on updates"}] {
  resource := input.resource_changes[_]
  resource.type == "aws_bedrockagent_agent_alias"
  not resource.change.after.routing_configuration
}