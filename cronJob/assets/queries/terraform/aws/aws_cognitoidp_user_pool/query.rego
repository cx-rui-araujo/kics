package main

__rego_metadata__ := {
  "id": "KICS_CUSTOM_AWS_COGNITO_ADMIN_NO_SRP_AUTH_FLOW",
  "title": "Cognito User Pool should not allow ADMIN_NO_SRP_AUTH flow",
  "description": "Enabling the ADMIN_NO_SRP_AUTH additional security flow bypasses Secure Remote Password protocol, weakening user authentication.",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
  "platform": "Terraform",
  "providers": ["aws"]
}

violation[resource] {
  resource := input.terraform.resources[_]
  resource.type == "aws_cognitoidp_user_pool"
  flows := resource.values.user_pool_add_ons.advanced_security_additional_flows
  flows[_] == "ADMIN_NO_SRP_AUTH"
}