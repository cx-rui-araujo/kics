package tfcognito

import data.tfconfig as tfconfig

__rego_metadata__ := {
  "id": "TF_AWS_COGNITO_NO_REFRESH_TOKEN_ROTATION",
  "version": "1.0.0",
  "short_code": "no-refresh-token-rotation",
  "severity": "MEDIUM",
  "type": "VIOLATION",
  "query": "ensure-cognito-refresh-token-rotation-enabled",
  "description": "Refresh token rotation is disabled for AWS Cognito User Pool Client, which may allow token reuse and replay attacks.",
  "provider": "terraform",
  "resource_type": "aws_cognito_user_pool_client"
}

deny[violation] {
  resource := tfconfig.resource.aws_cognito_user_pool_client[name]
  resource.values.refresh_token_rotation == false
  violation := {
    "resource": resource.address,
    "message": "Refresh token rotation is disabled, consider enabling it to prevent token replay attacks."
  }
}