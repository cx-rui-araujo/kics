package main

violation[{"msg": msg, "resource": resource}] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  flows := resource.change.after.user_pool_add_ons.advanced_security_additional_flows
  flows[_] == "CUSTOM_CHALLENGE"
  msg := "Custom challenge flow enabled in advanced security additional flows, which may allow bypass of authentication controls."
}