package cloud

__rego_metadata__ := {
  "id": "AWS_COGNITO_ADVANCED_FLOWS_01",
  "title": "Cognito User Pool should not allow custom authentication flows",
  "severity": "HIGH",
  "type": "VIOLATION",
  "resource": "aws_cognitoidp_user_pool"
}

deny[msg] {
  input.resource_type == "aws_cognitoidp_user_pool"
  addons := input.user_pool_add_ons
  flows := addons.advanced_security_additional_flows
  flows != null
  flow := flows[_]
  flow == "ALLOW_CUSTOM_AUTH"
  msg = sprintf("Resource '%s' allows custom auth flow in advanced_security_additional_flows, which may bypass protections", [input.name])
}