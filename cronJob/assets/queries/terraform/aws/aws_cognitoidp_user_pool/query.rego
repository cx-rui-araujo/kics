package terraform.aws.cognito_insecure_additional_flows

__rego_metadata__ := {
  "id": "AWS005",
  "title": "AWS Cognito User Pool Should Not Allow ADMIN_NO_SRP_AUTH Flow",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "uri": "cognito_user_pool_additional_flows"
}

violation[message] {
  input.resource_type == "aws_cognitoidp_user_pool"
  addons := input.resource.values.user_pool_add_ons
  addons.advanced_security_additional_flows[_] == "ADMIN_NO_SRP_AUTH"
  message := "Resource 'aws_cognitoidp_user_pool' allows ADMIN_NO_SRP_AUTH in advanced_security_additional_flows which can bypass SRP authentication and weaken security."
}