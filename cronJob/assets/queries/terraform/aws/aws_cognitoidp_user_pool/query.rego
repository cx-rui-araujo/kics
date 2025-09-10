package terraform.aws.Cognito

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  after := resource.change.after
  flows := after.user_pool_add_ons.advanced_security_additional_flows
  flows[_] == "ALLOW_CUSTOM_AUTH"
}