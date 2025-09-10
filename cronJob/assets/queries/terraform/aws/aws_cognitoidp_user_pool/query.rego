package aws.cognito

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  flows := resource.change.after.user_pool_add_ons.advanced_security_additional_flows
  flows != null
  msg := sprintf("Cognito User Pool '%s' has advanced_security_additional_flows enabled, which may allow authentication bypass.", [resource.change.after.name])
}