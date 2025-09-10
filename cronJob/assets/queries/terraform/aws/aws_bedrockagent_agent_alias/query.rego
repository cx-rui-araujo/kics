package kics

violation[{
  "resource": resource.address,
  "msg": msg,
}] {
  resource := input.resources[_]
  resource.type == "aws_bedrockagent_agent_alias"
  not resource.values.routing_configuration
  msg := "aws_bedrockagent_agent_alias should explicitly define routing_configuration to avoid unintended or unauthorized traffic routing."
}