package main

__rego["id"] = "KICS_AWS_9999"
__rego["severity"] = "MEDIUM"
__rego["categories"] = ["security"]
__rego["subject"] = "refresh_token_rotation"
__rego["provider"] = "aws"
__rego["service"] = "cognito"
__rego["short_code"] = "enable-refresh-token-rotation"

deny[msg] {
  input.kind == "resource"
  input.type == "aws_cognito_user_pool_client"
  not input.values.refresh_token_rotation
  msg := sprintf("Cognito user pool client '%s' should enable refresh_token_rotation to prevent token reuse attacks", [input.values.name])
}