package check_aws_bedrockagent_agent_alias

deny[msg] {
  resource := input.resource
  resource.Type == "aws_bedrockagent_agent_alias"
  not resource.Config.routing_configuration
  msg := sprintf("Resource '%s' is missing explicit routing_configuration, which may unintentionally inherit old routing and expose outdated agent versions.", [resource.Address])
}