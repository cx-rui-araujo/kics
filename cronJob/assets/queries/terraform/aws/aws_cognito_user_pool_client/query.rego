package main

import data.terraform

__rego_metadata__ := {
  "id": "AWS023",
  "version": "1.0.0",
  "title": "Ensure AWS Cognito User Pool Client has refresh token rotation enabled",
  "description": "Refresh token rotation forces new refresh tokens upon token refresh, reducing risk of token replay attacks.",
  "severity": "MEDIUM",
  "recommended_actions": ["Enable the refresh_token_rotation attribute to true in aws_cognito_user_pool_client resources."],
  "links": ["https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool_client#refresh_token_rotation"]
}

violation[{"msg": msg, "resource": resource.address}] {
  resource := data.terraform.aws_cognito_user_pool_client[_]
  resource.values.refresh_token_rotation == false
  msg := sprintf("Resource '%s' does not have refresh_token_rotation enabled.", [resource.address])
}