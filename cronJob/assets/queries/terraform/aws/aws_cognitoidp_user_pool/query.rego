package main

__rego_metadata__ = {
  "id": "KICS-CRITICAL-1",
  "title": "Cognito User Pool enables advanced_security_additional_flows",
  "severity": "MEDIUM",
  "type": "misconfiguration"
}

deny[violation] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  addons := resource.change.after.user_pool_add_ons
n  flows := addons.advanced_security_additional_flows
  count(flows) > 0

  violation := {
    "message": sprintf("Resource '%v' configures advanced_security_additional_flows: %v, which may weaken risk-based authentication.", [resource.address, flows])
  }
}