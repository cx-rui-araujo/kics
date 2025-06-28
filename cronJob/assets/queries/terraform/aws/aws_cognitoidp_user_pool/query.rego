# @id KICS-AWS-001
# @title AWS Cognito: avoid insecure advanced security flow
# @severity HIGH
package main

violation[{"msg": msg, "resource": res.change.after.name}] {
  res := input.resource_changes[_]
  res.type == "aws_cognitoidp_user_pool"
  after := res.change.after
  addons := after.user_pool_add_ons
  flows := addons.advanced_security_additional_flows
  flows[_] == "admin_user_password"
  msg := sprintf("aws_cognitoidp_user_pool '%s' has insecure advanced_security_additional_flow 'admin_user_password' enabled", [after.name])
}