package kics

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  after := resource.change.after
  addons := after.user_pool_add_ons
  addons.advanced_security_additional_flows[_] == "ALLOW_USER_PASSWORD_AUTH"
}