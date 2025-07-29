package terraform.aws_cognitoidp_user_pool

violation[resource] {
  resource := input.resource
  resource.Type == "aws_cognitoidp_user_pool"
  addons := resource.Values.user_pool_add_ons
  flows := addons.advanced_security_additional_flows
  some i
  flows[i] == "ALLOW_CUSTOM_AUTH"
}