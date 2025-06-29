package terraform

__rego_metadata__ := {
  "id": "AWS_COGNITO_SRP_BYPASS",
  "title": "Cognito user pool should not allow ADMIN_NO_SRP_AUTH flows",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

deny[msg] {
  input.resource.Type == "aws_cognitoidp_user_pool"
  attrs := input.resource.Primary.Attributes
  count({k | startswith(k, "user_pool_add_ons.0.advanced_security_additional_flows.")
      and attrs[k] == "ADMIN_NO_SRP_AUTH"}) > 0
  msg := sprintf("User pool '%s' has insecure additional flow 'ADMIN_NO_SRP_AUTH' configured", [attrs["name"]])
}