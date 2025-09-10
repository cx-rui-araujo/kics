package custom

violation[res] {
  rc := input.ResourceChanges[_]
  rc.Type == "aws_cognitoidp_user_pool"
  flows := rc.Change.After.user_pool_add_ons.advanced_security_additional_flows
  flows[_] == "ADMIN_USER_PASSWORD_AUTH"
  res := {"resource": rc.Address, "message": "Enabling ADMIN_USER_PASSWORD_AUTH in advanced_security_additional_flows bypasses SRP authentication and may expose credentials."}
}