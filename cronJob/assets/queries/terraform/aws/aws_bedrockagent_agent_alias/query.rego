package kics

__rego_metadata__ := {
  "id": "AWS_BEDROCK_004",  # Custom rule ID
  "title": "Ensure routing_configuration is explicitly set on aws_bedrockagent_agent_alias",
  "severity": "MEDIUM"
}

violation[{
  "resource": resource.FullName(),
  "msg": "The aws_bedrockagent_agent_alias resource must explicitly configure routing_configuration to avoid stale or unintended routes."
}] {
  resource := input.Blocks[_]
  resource.Type == "resource"
  resource.Labels[0] == "aws_bedrockagent_agent_alias"
  not resource.Body.HasChild("routing_configuration")
}