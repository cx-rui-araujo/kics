package terraform.aws

__rego_metadata__ := {
  "id": "AWS_BEDROCK_001",
  "title": "Missing routing_configuration in aws_bedrockagent_agent_alias",
  "severity": "MEDIUM",
  "type": "Misconfiguration",
  "metadata": {"description": "Ensure aws_bedrockagent_agent_alias includes an explicit routing_configuration to avoid stale or unintended routing settings."}
}

deny[resource] {
  resource := tfconfig.resource["aws_bedrockagent_agent_alias"][name]
  not resource.block.HasChild("routing_configuration")
}