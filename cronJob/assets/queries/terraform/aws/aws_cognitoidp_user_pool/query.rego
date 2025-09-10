package tfplan

__rego_metadata__ := {
  "id": "AWS_COGNITO_ADV_SEC_CUSTOM_AUTH",
  "title": "Cognito User Pool should not allow custom auth flow in advanced security",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "platform": "Terraform",
  "resource_type": "aws_cognitoidp_user_pool"
}

denied[message] {
  resource := input.resource_changes[_]
  resource.change.after.type == "aws_cognitoidp_user_pool"
  addons := resource.change.after.value.user_pool_add_ons
  flows := addons.advanced_security_additional_flows
  flow := flows[_]
  flow == "ALLOW_CUSTOM_AUTH"
  message := sprintf("Resource '%s' uses ALLOW_CUSTOM_AUTH in advanced_security_additional_flows, which can enable insecure custom auth flows.", [resource.change.after.address])
}