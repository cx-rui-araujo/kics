package main

__rego_metadata__ := {
  "id": "AWS_42470",
  "version": "1.0.0",
  "title": "Ensure Cognito User Pool does not enable additional security flows",
  "severity": "HIGH"
}

deny[msg] {
  input.resource.type == "aws_cognitoidp_user_pool"
  addons := input.resource.values.user_pool_add_ons
  addons != null
  flows := addons.advanced_security_additional_flows
  flows != null
  count(flows) > 0
  msg := sprintf("Cognito User Pool '%s' enables advanced_security_additional_flows, which may expose deprecated or insecure authentication paths.", [input.resource.values.name])
}