package main

# KICS AWS Cognito User Pool Client should enable refresh token rotation
# ID: KICS-AWS-999
# Severity: MEDIUM
# Category: Authentication
# Description: Disabling refresh_token_rotation allows stolen refresh tokens to be reused indefinitely.

violation[{
  "msg": msg,
  "resource": resource.Address
}] {
  resource := input.resources[_]
  resource.Type == "aws_cognito_managed_user_pool_client"
  # If refresh_token_rotation is missing or set to false, flag as violation
  not resource.Config.refresh_token_rotation
  msg := sprintf("Cognito User Pool Client '%s' does not have refresh_token_rotation enabled. Stolen refresh tokens may be reused indefinitely.", [resource.Name])
}