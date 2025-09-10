package aws

__rego_metadata__ := {
  "id": "AWS_BEDROCK_AGENT_ALIAS_NO_ROUTING_CFG",
  "title": "aws_bedrockagent_agent_alias without routing_configuration may remove alias routing on update",
  "severity": "MEDIUM",
  "type": "KICS",
  "documentation_url": "https://docs.kics.io/latest/queries/aws/best_practices/#no-routing-configuration"
}

violation[issue] {
  input.kind == "resource_changes"
  resource := input.resource_changes[_]
  resource.type == "aws_bedrockagent_agent_alias"
  # routing_configuration must be explicitly defined to avoid accidental removal on update
  not resource.change.after.routing_configuration
  issue := {
    "msg": sprintf("Resource '%s' is missing routing_configuration, may lead to alias routing removal on updates", [resource.address]),
    "resource": resource.address
  }
}