package main

deny[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  addons := resource.change.after.user_pool_add_ons
  addons.advanced_security_additional_flows[_] == "ADMIN_NO_SRP_AUTH"
}