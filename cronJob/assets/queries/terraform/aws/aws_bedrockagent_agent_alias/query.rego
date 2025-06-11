package main

__rego_metadata__ := {
  "id": "KICS-9999",
  "title": "Ensure aws_bedrockagent_agent_alias routing_configuration is set",
  "severity": "MEDIUM",
  "type": "MISCONFIGURATION",
  "status": "experimental"
}

violation[res] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_bedrockagent_agent_alias"
  not resource.change.after.routing_configuration
  res := {
    "ResourceName": resource.address,
    "Message": "aws_bedrockagent_agent_alias should explicitly configure routing_configuration to avoid alias version drift and insecure default routing"
  }
}