package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  resource.change.after.user_pool_add_ons.advanced_security_additional_flows
  msg := sprintf("aws_cognitoidp_user_pool '%s' has 'advanced_security_additional_flows' set, which may lead to privilege escalation if misconfigured", [resource.name])
}