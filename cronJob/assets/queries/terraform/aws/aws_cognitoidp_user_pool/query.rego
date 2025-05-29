package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  after := resource.change.after
  addons := after.user_pool_add_ons
  flows := addons.advanced_security_additional_flows
  flows.allow_custom_auth == true
  msg := sprintf("Resource '%s' enables custom auth flow in advanced_security_additional_flows which may bypass security checks", [resource.address])
}