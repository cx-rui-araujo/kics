package main

__rego__ version: "1.0.0"
__rego__ id: "AWS_COGNITO_REFRESH_TOKEN_ROTATION"
__rego__ title: "Ensure refresh_token_rotation is enabled for Cognito User Pool Clients"
__rego__ severity: "HIGH"
__rego__ category: "Security Best Practices"
__rego__ input: ["resource"]
__rego__ resource: "aws_cognito_managed_user_pool_client"
__rego__ scope: ["terraform"]

violation[client] {
  client := input.resource.aws_cognito_managed_user_pool_client[_]
  # Refresh token rotation must be enabled to prevent token replay attacks
  not client.refresh_token_rotation
}