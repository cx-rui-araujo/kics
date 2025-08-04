package main

__rego_metadata__ := {
  "id": "AWS_COGNITO_UNSAFE_FLOW",
  "title": "Ensure advanced_security_additional_flows does not allow insecure flows",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "provider": "AWS",
  "resource": "aws_cognitoidp_user_pool"
}

deny[msg] {
  input.resource_type == "aws_cognitoidp_user_pool"
  addons := input.change.after.user_pool_add_ons
  flows := addons.advanced_security_additional_flows
  contains(flows, "ADMIN_NO_SRP_AUTH")
  msg := sprintf("User pool %s enables insecure ADMIN_NO_SRP_AUTH flow", [input.address])
}