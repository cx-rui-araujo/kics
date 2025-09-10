package main

import input

__rego_metadata__ := {
    "id": "KICS_AWS_BEDROCKAGENT_AGENT_ALIAS_ROUTING",
    "title": "aws_bedrockagent_agent_alias missing explicit routing_configuration",
    "severity": "LOW",
    "type": "KICS",
    "description": "Ensure aws_bedrockagent_agent_alias resources have an explicit routing_configuration to avoid unintended alias versions.",
    "documentation_url": "https://docs.kics.io/latest/queries/aws/bedrockagent"
}

violation[message] {
    resource := input.resource_changes[_]
    resource.type == "aws_bedrockagent_agent_alias"
    not resource.change.after.routing_configuration
    message := sprintf(
        "Resource '%s' missing explicit routing_configuration, which may lead to unintended alias versions",
        [resource.address]
    )
}