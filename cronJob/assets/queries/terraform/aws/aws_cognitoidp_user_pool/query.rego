package custom

import input

# Warn when insecure ADMIN_NO_SRP_AUTH flow is enabled in Cognito advanced security additional flows
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  after := resource.change.after
  addons := after.user_pool_add_ons[0]
  flows := addons.advanced_security_additional_flows
  flows[_] == "ADMIN_NO_SRP_AUTH"
  msg := sprintf("AWS Cognito User Pool '%s' allows insecure ADMIN_NO_SRP_AUTH auth flow in advanced_security_additional_flows", [after.name])
}