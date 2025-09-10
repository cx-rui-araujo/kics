###
{"id":"AWS_COGNITO_REFRESH_TOKEN_ROTATION","title":"Enable refresh token rotation for Cognito user pool client","description":"Detects when refresh_token_rotation is disabled in aws_cognito_user_pool_client, which may allow reuse of refresh tokens indefinitely.","severity":"HIGH","platform":"AWS","category":"Security Best Practices"}
###
package custom.aws

deny[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  args := resource.change.after
  args.refresh_token_rotation == false
}
