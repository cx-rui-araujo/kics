package main

__rego_metadata__ = {"id": "AWS_COGNITO_USER_POOL_1", "title": "Prevent advanced_security_additional_flows in Cognito User Pools", "severity": "HIGH", "type": "Misconfiguration"}

deny[msg] {
    resource := input.resource
    resource.type == "aws_cognitoidp_user_pool"
    addons := resource.values.user_pool_add_ons
    flows := addons.advanced_security_additional_flows
    count(flows) > 0
    msg := sprintf("Resource '%s' should not have advanced_security_additional_flows enabled: %v", [resource.name, flows])
}