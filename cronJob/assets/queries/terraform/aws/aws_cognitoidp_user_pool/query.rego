package terraform.aws.CognitoAdditionalFlows

violation[resource] {
  resource := input.Resources[_]
  resource.Type == "aws_cognitoidp_user_pool"
  addons := resource.Values.user_pool_add_ons
  addons.advanced_security_additional_flows[_] == "ALLOW_ADMIN_USER_PASSWORD_AUTH"
}