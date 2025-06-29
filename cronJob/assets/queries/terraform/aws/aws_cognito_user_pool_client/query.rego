package main
import data.terraform.tfstate as tfstate

violation[{"message": msg, "metadata": {"resource": address}}] {
  resource := tfstate.resources.aws_cognito_user_pool_client[_]
  resource.values.refresh_token_rotation == false
  msg := sprintf("aws_cognito_user_pool_client '%s' should have refresh_token_rotation enabled to prevent token replay attacks.", [resource.address])
  address := resource.address
}