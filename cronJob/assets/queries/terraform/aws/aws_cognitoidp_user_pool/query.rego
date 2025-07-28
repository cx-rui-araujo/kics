package kics

violation[{"msg": msg, "resource": resource}] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  addons := resource.change.after.user_pool_add_ons
  addons.advanced_security_mode == "ENABLED"
  flows := addons.advanced_security_additional_flows
  flows[_] == "ADMIN_NO_SRP_AUTH"
  msg := "Enabling ADMIN_NO_SRP_AUTH in advanced_security_additional_flows may allow bypassing user authentication leading to unauthorized access."
}