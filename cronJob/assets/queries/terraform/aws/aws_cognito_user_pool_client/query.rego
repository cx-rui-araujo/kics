package main

import data.terraform as tf

__rego_metadata__ := {
  "id": "AWS_COGNITO_REFRESH_TOKEN_ROTATION",
  "title": "Enable refresh_token_rotation for aws_cognito_user_pool_client",
  "description": "Refresh token rotation should be enabled to prevent token replay risks.",
  "severity": "HIGH",
  "recommendation": "Set refresh_token_rotation = true",
  "platform": "Terraform"
}

violation[resource] {
  resource := tf.resource["aws_cognito_user_pool_client"][name]
  not resource.config.refresh_token_rotation
}
