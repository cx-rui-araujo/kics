package terraform_aws

__rego_metadata__ = {
  id: "AWS_BEDROCK_001",
  title: "Ensure routing_configuration defined for aws_bedrockagent_agent_alias",
  severity: "MEDIUM",
  type: "VULNERABILITY",
  description: "Missing routing_configuration may lead to retaining stale configuration on updates.",
  reference_id: "AWS.BedrockAgentAgentAlias.NoRoutingConfig",
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_bedrockagent_agent_alias"
  not resource.change.after.routing_configuration
}