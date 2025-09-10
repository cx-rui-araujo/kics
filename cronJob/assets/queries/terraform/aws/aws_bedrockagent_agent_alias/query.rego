package kics

__rego_metadata__ := {
  "id": "KICS-AWS-001",
  "title": "Missing routing_configuration for aws_bedrockagent_agent_alias",
  "severity": "MEDIUM",
  "type": "Misconfiguration",
}

violation[report] {
  res := input.resource_changes[_]
  res.type == "aws_bedrockagent_agent_alias"
  not res.change.after.routing_configuration
  report := {
    "message": "Explicit routing_configuration should be defined for aws_bedrockagent_agent_alias to avoid unintended alias routing.",
    "resource": res.address,
  }
}