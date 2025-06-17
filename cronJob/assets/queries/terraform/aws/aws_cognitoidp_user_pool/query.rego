package tfcognito

import tfconfig

deny[msg] {
  resource := tfconfig.resources["aws_cognitoidp_user_pool"][name]
  flows := resource.values.user_pool_add_ons.advanced_security_additional_flows
  flows.admin_user_password_auth
  msg := sprintf("Cognito user pool '%s' enables admin_user_password_auth, bypassing advanced security checks", [name])
}