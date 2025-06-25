package aws

__metadata__ = {
  "id": "AWS057",
  "version": "1.0",
  "title": "Insecure AWS Cognito advanced_security_additional_flows",
  "severity": "HIGH",
  "description": "Detects when ADMIN_NO_SRP_AUTH flow is enabled, which bypasses SRP authentication and is insecure.",
  "provider": "aws",
  "resource": "aws_cognitoidp_user_pool"
}

denies[message] {
  input.resource_changes[_].type == "aws_cognitoidp_user_pool"
  after := input.resource_changes[_].change.after
  flows := after.user_pool_add_ons.advanced_security_additional_flows
  flows[_] == "admin_no_srp_auth"
  message := sprintf("Cognito User Pool '%s' has insecure ADMIN_NO_SRP_AUTH flow enabled.", [after.name])
}