package aws.cognito

__rego_metadata__ := {
  "id": "AWS004",
  "title": "Cognito User Pool Client with refresh_token_rotation disabled",
  "severity": "MEDIUM",
  "type": "VULNERABILITY"
}

violation[resource] {
  resource := input.resource
  resource.Type == "aws_cognito_managed_user_pool_client"
  not resource.Values.refresh_token_rotation
}