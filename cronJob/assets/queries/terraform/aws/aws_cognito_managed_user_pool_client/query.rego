package kics

__rego_metadata__ = {
  "id": "KICS_AWS_60",
  "title": "Ensure refresh token rotation is enabled for Cognito user pool clients",
  "severity": "MEDIUM",
  "type": "Misconfiguration",
  "platform": "terraform"
}

deny[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  not resource.change.after.refresh_token_rotation
}