package kics

default deny = false

deny[msg] {
  input.resource_changes[_] = change
  change.type == "aws_cognitoidp_user_pool"
  after := change.change.after
  flows := after.user_pool_add_ons.advanced_security_additional_flows
  flows[_] == "ALLOW_ADMIN_USER_PASSWORD_AUTH"
  msg = "aws_cognitoidp_user_pool is configured with ALLOW_ADMIN_USER_PASSWORD_AUTH which may allow bypassing MFA and weaken security"
}