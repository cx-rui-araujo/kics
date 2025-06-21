package kics

__rego_metadata__ := {
  "id": "AWS_COGNITO_001",
  "title": "Cognito User Pool allows ADMIN_USER_PASSWORD_AUTH flow",
  "description": "Enabling ADMIN_USER_PASSWORD_AUTH in advanced_security_additional_flows allows raw password authentication and may expose credentials.",
  "severity": "MEDIUM",
  "rule_type": "VIOLATION",
  "platform": "Terraform"
}

denied_resources[resource] {
  resource := input.resource
  resource.type == "aws_cognitoidp_user_pool"
  flows := resource.values.user_pool_add_ons.advanced_security_additional_flows
  flows[_] == "ADMIN_USER_PASSWORD_AUTH"
}