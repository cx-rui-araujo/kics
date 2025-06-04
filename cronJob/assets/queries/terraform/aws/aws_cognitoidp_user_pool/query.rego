package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  flows := resource.change.after.user_pool_add_ons.advanced_security_additional_flows
  count(flows) > 0
  msg := sprintf("Cognito User Pool '%v' has advanced_security_additional_flows enabled, increasing attack surface.", [resource.address])
}