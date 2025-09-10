package main

# Detect aws_bedrockagent_agent_alias without explicit routing_configuration
violation[resource] {
  resource := input.blocks[_]
  resource.Type == "resource"
  # Ensure this is the Bedrock Agent Alias resource
  resource.Labels[0] == "aws_bedrockagent_agent_alias"
  # Check that routing_configuration is not defined, which may indicate unintended removal
  not resource.Body.Attributes.routing_configuration
}