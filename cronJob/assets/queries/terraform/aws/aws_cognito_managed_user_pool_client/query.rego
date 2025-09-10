package main

__rego_metadoc__ := {"id": "AWS_COGNITO_001", "title": "Ensure refresh token rotation is enabled for Cognito user pool clients", "severity": "HIGH", "category": "Authentication and Authorization"}

violation[resource] {
  resource := input.resource.aws_cognito_managed_user_pool_client[_]
  not resource.config.refresh_token_rotation
}