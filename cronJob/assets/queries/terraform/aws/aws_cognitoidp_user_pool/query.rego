package terraform.aws.CognitoUserPoolAdvancedSecurityAdditionalFlows

# Identifies Cognito User Pools with high-risk additional authentication flows enabled
violation[resource, msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  addons := resource.change.after.user_pool_add_ons.advanced_security_additional_flows
  addons != null
  count(addons) > 0
  msg := sprintf("Resource %v enables high-risk advanced_security_additional_flows: %v", [resource.address, addons])
}