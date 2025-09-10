package terraform.aws.CognitoInsecureAdditionalFlows

__rego_metadata__ = {
  "id": "KICS_AWS_99",
  "title": "Ensure Cognito user pool advanced security additional flows do not allow admin user password auth",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

deny[msg] {
  resource := input.resource
  resource.type == "aws_cognitoidp_user_pool"
  addons := resource.values.user_pool_add_ons
  flow := addons.advanced_security_additional_flows[_]
  flow == "ALLOW_ADMIN_USER_PASSWORD_AUTH"
  msg := sprintf("Cognito user pool '%v' allows '%v' flow which can bypass SRP", [resource.name, flow])
}