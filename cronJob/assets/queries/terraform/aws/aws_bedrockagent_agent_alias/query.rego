package main

__rego_metadata__ = {
    "id": "KICS-999",
    "version": "1.0.0",
    "title": "Missing explicit routing_configuration for aws_bedrockagent_agent_alias",
    "description": "If routing_configuration is not explicitly set, updates may unintentionally not create new versions of the alias.",
    "severity": "LOW",
    "uri": "https://docs.kics.io/latest/creating-queries/"
}

violation[resource] {
    resource := input.resource[_]
    resource.type == "aws_bedrockagent_agent_alias"
    not resource.values.routing_configuration
}