package kics

__rego_metadata__ := {
  "id": "KICS-0001",
  "title": "Cognito User Pool Client without refresh token rotation",
  "severity": "MEDIUM",
  "type": "Terraform Security Check"
}

deny[resource] {
  resource := input.HCL.Blocks[_]
  resource.Type == "resource"
  resource.Labels[0] == "aws_cognito_managed_user_pool_client"
  (
    not resource.Body.Attributes["refresh_token_rotation"]
    or resource.Body.Attributes["refresh_token_rotation"].Value == false
  )
}