package tfplan

violation[res] {
  input.resource_changes[_].type == "aws_cognitoidp_user_pool"
  after := input.resource_changes[_].change.after
  after.user_pool_add_ons.advanced_security_additional_flows
  res := {
    "resource": input.resource_changes[_].address,
    "msg": "Enabling `user_pool_add_ons.advanced_security_additional_flows` may weaken security posture by allowing bypass of standard authentication flows."
  }
}