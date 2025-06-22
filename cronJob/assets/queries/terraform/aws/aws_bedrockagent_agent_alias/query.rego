package aws_bedrockagent

violation[{"msg": msg, "resource": name}] {
  resource := input.resource.aws_bedrockagent_agent_alias[name]
  not resource.values.routing_configuration
  msg := sprintf("aws_bedrockagent_agent_alias '%s' must explicitly configure routing_configuration to prevent unintended routing defaults", [name])
}