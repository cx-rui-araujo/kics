package terraform

__rego_metadata__ = {"id": "KICS-IMAGINARY-001", "title": "Imaginary aws_bedrockagent_agent misconfigurations", "description": "Detects manual assignment of prepared_at and overly long instruction values in aws_bedrockagent_agent resources.", "severity": "MEDIUM"}

violation[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_bedrockagent_agent"
    resource.change.after.prepared_at != null
}

violation[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_bedrockagent_agent"
    instruction := resource.change.after.instruction
    count(split(instruction, "")) > 10000
}
