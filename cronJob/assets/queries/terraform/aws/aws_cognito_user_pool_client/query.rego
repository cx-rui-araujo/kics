package aws_cognito_user_pool_client

__rego_metadata__ := {
  "id": "KICS-42430",
  "title": "Cognito user pool client refresh_token_rotation must be enabled",
  "severity": "MEDIUM",
  "type": "VULNERABILITY"
}

deny[violation] {
  resource := input.Resources[_]
  resource.Type == "aws_cognito_user_pool_client"
  not resource.Values.refresh_token_rotation
  violation := {
    "msg": sprintf("Cognito user pool client '%s' has refresh_token_rotation disabled, increasing risk of stolen refresh tokens.", [resource.Name]),
    "resource": resource.Name
  }
}