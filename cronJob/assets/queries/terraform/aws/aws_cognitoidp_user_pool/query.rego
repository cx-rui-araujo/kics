package terraform.aws.CognitoUserPoolAdvancedSecurityAdditionalFlows

__rego_metadata__ := {
  id: "KICS-9999",
  title: "Cognito User Pool allows insecure additional flows",
  severity: "HIGH",
  type: "terraform",
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognitoidp_user_pool"
  after := resource.change.after.user_pool_add_ons.advanced_security_additional_flows
  some i
  after[i] == "ALLOW_ADMIN_USER_PASSWORD_AUTH"
}