package aws.cognito

violation[{"resource": addr, "message": msg}] {
  rc := input.resource_changes[_]
  rc.type == "aws_cognitoidp_user_pool"
  after := rc.change.after
  # flag if insecure additional flow is enabled
  flows := after.user_pool_add_ons.advanced_security_additional_flows
  flows[_] == "ALLOW_ADMIN_USER_PASSWORD_AUTH"
  addr := rc.address
  msg := sprintf("Cognito User Pool '%s' has insecure additional flow ALLOW_ADMIN_USER_PASSWORD_AUTH enabled", [addr])
}