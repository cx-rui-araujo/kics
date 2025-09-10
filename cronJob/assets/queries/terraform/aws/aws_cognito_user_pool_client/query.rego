package aws.cognito.userpool.client

__rego_meta__ = {
  "id": "KICS_AWS_COGNITO_USER_POOL_CLIENT_1",
  "title": "Ensure refresh token rotation is enabled for AWS Cognito User Pool Clients",
  "description": "Disabling refresh token rotation can lead to reuse of stolen refresh tokens and potential session hijacking.",
  "severity": "HIGH",
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  # refresh_token_rotation must be set to true
  not resource.change.after.refresh_token_rotation
}