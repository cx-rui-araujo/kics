package aws_cognitoidp

deny[message] {
  resource := input.resource.aws_cognitoidp_user_pool[_]
  addons := resource.user_pool_add_ons[0].advanced_security_additional_flows
  contains(addons, "ADMIN_NO_SRP_AUTH")
  message := sprintf("Cognito user pool '%s' has ADMIN_NO_SRP_AUTH enabled, which may allow unauthorized admin authentication flows.", [resource.name])
}