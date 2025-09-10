package terraform.security

violation[{"resource": resource.address, "metadata": {"description": "Custom authentication flows may bypass advanced security checks.", "severity": "HIGH", "id": "AWS_COGNITOIDP_USER_POOL_CUSTOM_AUTH"}}] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  addons := resource.after.user_pool_add_ons
  flows := addons.advanced_security_additional_flows
  flows[_] == "ALLOW_CUSTOM_AUTH"
}