package main

__rego_metadata__ = {"id": "KICS_CUSTOM_AWS_RefreshTokenRotation", "version": "1.0.0", "title": "Ensure Cognito User Pool Client has refresh_token_rotation enabled", "severity": "MEDIUM"}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  not resource.change.after.refresh_token_rotation
  msg := sprintf("Cognito User Pool Client '%s' does not have refresh_token_rotation enabled", [resource.address])
}