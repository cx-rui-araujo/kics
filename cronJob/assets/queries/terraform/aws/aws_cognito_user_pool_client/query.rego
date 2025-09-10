package terraform.aws

deny[message] {
  resource := input.resource["aws_cognito_user_pool_client"]
  resource != null
  attr := resource[0].primary.attributes.refresh_token_rotation
  attr == "false"
  message := sprintf("Cognito user pool client '%s' has refresh_token_rotation disabled, which can enable token replay attacks.", [resource[0].primary.id])
}