package aws.cognito

default allow = false

# Deny if refresh_token_rotation is not enabled on Cognito user pool clients
violation[{{"msg": msg}}] {
  input.kind == "aws_cognito_user_pool_client"
  # refresh_token_rotation must be true
  not input.spec.refresh_token_rotation
n  msg := "Cognito User Pool Client has refresh_token_rotation disabled or unset, which allows refresh token reuse and increases risk of token theft."  
}