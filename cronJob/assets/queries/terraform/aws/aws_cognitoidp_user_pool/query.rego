package main

# Deny if ADMIN_NO_SRP_AUTH is enabled in advanced_security_additional_flows
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  after := resource.change.after
  addons := after.user_pool_add_ons
  flows := addons.advanced_security_additional_flows
  contains(flows, "ADMIN_NO_SRP_AUTH")
  msg = "Cognito user pool advanced_security_additional_flows contains ADMIN_NO_SRP_AUTH, bypassing SRP authentication is insecure."
}