package main

import data.terraform

__rego_metadata__ = {
  "id": "KICS-AWS-COGNITO-001",
  "version": "1.0.0",
  "title": "Enable refresh token rotation for Cognito user pool clients",
  "severity": "MEDIUM",
  "category": "Security Best Practices",
  "description": "Ensure refresh_token_rotation is enabled to prevent refresh token reuse."
}

deny[msg] {
  resource := terraform.resources[_]
  resource.type == "aws_cognito_user_pool_client"
  not resource.values.refresh_token_rotation
  msg := sprintf("Cognito user pool client '%s' should have refresh_token_rotation enabled", [resource.name])
}