package main

violation[res] {
    resource := input.resource_changes[_]
    resource.type == "aws_cloudwatch_event_bus"
    dead := resource.change.after.dead_letter_config
    dead != null
    contains(dead.arn, "*")
    res := {
        "msg": sprintf("aws_cloudwatch_event_bus '%s' has wildcard ARN '%s' in dead_letter_config", [resource.address, dead.arn]),
        "resource": resource.address
    }
}