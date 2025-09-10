package aws.bedrockagent.alias_missing_routing_configuration

__rego_metadata__ := {
  "id": "AWS_BEDROCK_ALIAS_ROUTING_CFG_1",
  "title": "Bedrock Agent Alias missing explicit routing_configuration",
  "description": "Ensure routing_configuration is explicitly set on aws_bedrockagent_agent_alias to avoid alias updates using default insecure routing.",
  "severity": "MEDIUM",
  "platform": "Terraform"
}

violation[issue] {
  resource := data.terraform.resources[_]
  resource.type == "aws_bedrockagent_agent_alias"
  not resource.values.routing_configuration
  issue := {
    "message": sprintf("Resource '%s' does not have routing_configuration explicitly configured", [resource.address]),
    "resource": resource.address
  }
}