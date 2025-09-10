package terraform.aws.CognitoManagedUserPoolClient

__rego_metadata__ = {
  "id": "AWSUnusedRefreshTokenRotation",
  "title": "Cognito User Pool Clients should enable Refresh Token Rotation",
  "description": "Disabling refresh token rotation allows older refresh tokens to be reused, increasing the risk of token replay attacks.",
  "severity": "HIGH",
  "confidence": "HIGH",
  "related_resources": ["aws_cognito_managed_user_pool_client"]
}

violation[res] {
  resource := input.resource[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  attrs := resource.instances[_].attributes
  not attrs.refresh_token_rotation
  res := {
    "message": sprintf("Resource '%s' does not have refresh_token_rotation enabled", [resource.address])
  }
}