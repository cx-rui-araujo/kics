// @id AWS_COGNITO_REFRESH_TOKEN_ROTATION
// @title Ensure AWS Cognito User Pool Client has refresh token rotation enabled
// @type misconfiguration
// @severity MEDIUM
package aws

import data.terraform.tfconfig as tfconfig

violation[resource] {
  resource := tfconfig.resource.aws_cognito_managed_user_pool_client[_]
  resource.values.refresh_token_rotation == false
}