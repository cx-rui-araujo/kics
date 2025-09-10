package kics

__rego_metadata__ := {
    "id": "AWS_BEDROCKAGENT_AGENT_ALIAS_ROUTING_CONFIGURATION_MISSING",
    "title": "Missing routing_configuration in aws_bedrockagent_agent_alias",
    "severity": "HIGH",
    "type": "misconfiguration",
    "description": "The provider change may omit the routing_configuration when not explicitly set, leading to unintended alias behavior or downtime.",
    "recommended_actions": "Ensure that routing_configuration is always explicitly defined in aws_bedrockagent_agent_alias resources.",
    "reference": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/bedrockagent_agent_alias"
}

deny[output] {
    input.resource_changes[_].type == "aws_bedrockagent_agent_alias"
    change := input.resource_changes[_].change.after
    not change.routing_configuration
    output := {
        "message": sprintf("aws_bedrockagent_agent_alias '%v' does not explicitly configure routing_configuration", [input.resource_changes[_].address]),
        "severity": __rego_metadata__.severity,
        "resource": input.resource_changes[_].address
    }
}