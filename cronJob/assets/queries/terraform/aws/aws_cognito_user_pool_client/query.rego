package main

import data.terraform.plan as plan

violation[{"resource": r.address, "msg": msg}] {
  r := plan.resource_changes[_]
  r.type == "aws_cognito_user_pool_client"
  after := r.change.after
  not after.refresh_token_rotation
  msg := sprintf("Resource '%s' has refresh_token_rotation disabled; enable it to prevent token replay attacks", [r.address])
}