package terraform

violation[resource] {
  resource := data.terraform_resources["aws_cognito_user_pool_client"][_]
  resource.values.refresh_token_rotation == false
}