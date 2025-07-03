package main

import data.terraform.plan as plan

deny[msg] {
  resource := plan.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  after := resource.change.after
  after.user_pool_add_ons.advanced_security_additional_flows[_] == "USER_PASSWORD_AUTH"
  msg := sprintf("Cognito User Pool '%s' allows insecure additional auth flow 'USER_PASSWORD_AUTH'", [resource.address])
}