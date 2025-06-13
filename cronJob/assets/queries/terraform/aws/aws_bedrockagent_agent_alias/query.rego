---
id: KICS-AWS-1
metadata:
  title: "AWS Bedrock Agent Alias without explicit routing_configuration"
  description: "Terraform aws_bedrockagent_agent_alias resources should explicitly configure routing_configuration to avoid unintended alias updates creating new versions without routing_config."
  severity: MEDIUM
  category: "Misconfiguration"
  resource: ["aws_bedrockagent_agent_alias"]
  reference_id: "AWS::Bedrock::AgentAlias:RoutingConfiguration"
source: |
  package main

  deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_bedrockagent_agent_alias"
    resource.change.after.routing_configuration == null
    msg := sprintf("Resource %s missing routing_configuration", [resource.address])
  }