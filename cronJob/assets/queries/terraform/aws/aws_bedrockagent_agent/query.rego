package main

__rego_metadata__ := {
  "id": "AWS_BEDROCK_AGENT_INSTRUCTION_LENGTH",
  "title": "Ensure aws_bedrockagent_agent instruction length is reasonable",
  "severity": "MEDIUM",
  "type": "KICS",
  "service": "Terraform",
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_bedrockagent_agent"
  instruction := resource.change.after.instruction
  count(split(instruction, "")) > 10000
}