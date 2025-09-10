package main

import data.kics

__rego_metadata__ := {
  "id": "KICS_AWS_COGNITO_001",
  "version": "1.0",
  "title": "Cognito user pool client should enable refresh token rotation",
  "severity": "MEDIUM",
  "type": "security",
  "query": "terraform_cognito_disable_refresh_token_rotation"
}

deny[output] {
  resource := data.kics.resources.aws_cognito_managed_user_pool_client[_]
  not resource.values.refresh_token_rotation
  output := {
    "resource_id": resource.address,
    "message": "Refresh token rotation is disabled for cognito user pool client, which may allow reuse of stolen tokens."
  }
}