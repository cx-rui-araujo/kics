package kics

__rego_metadata__ = {
  "id": "AWS_BEDROCK_AGENT_ALIAS_ROUTING_CONFIG_CHECK",
  "version": "1.0",
  "title": "Ensure routing_configuration is explicitly set for aws_bedrockagent_agent_alias",
  "description": "Routing configuration should be explicitly set to avoid unintended alias behavior.",
  "severity": "HIGH",
  "type": "KICS_CUSTOM_CHECK"
}

violation[alias] {
  alias := input.resource_changes[_]
  alias.type == "aws_bedrockagent_agent_alias"
  not alias.change.after.routing_configuration
}