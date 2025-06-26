package main
import data.terraform_plan as tfplan

violation[{"resource": r.address, "message": msg}] {
  r := tfplan.resource_changes[_]
  r.type == "aws_cognito_managed_user_pool_client"
  not r.change.after.refresh_token_rotation
  msg := sprintf("Resource %v has refresh_token_rotation disabled or not set", [r.address])
}