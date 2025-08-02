package terraform.aws.cognito

__rego_metadata__ := {
  "id": "AWS060",
  "title": "Cognito User Pool Client Refresh Token Rotation should be enabled",
  "severity": "MEDIUM",
  "type": "VULNERABILITY"
}

violation[resource] {
  resource := input.resource
  resource.Type == "aws_cognito_user_pool_client"
  not resource.Values.refresh_token_rotation
}