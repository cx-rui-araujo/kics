package aws.cognito

import data.tfconfig as tfconfig

# Rule: Ensure refresh_token_rotation is enabled to prevent token replay attacks
violation[resource] {
  resource := tfconfig.resource["aws_cognito_managed_user_pool_client"][name]
  not resource.refresh_token_rotation
  resource_address := sprintf("%s.%s", [resource.type, name])
  msg := sprintf("Cognito User Pool Client '%s' should enable refresh_token_rotation to avoid replay vulnerabilities.", [resource_address])
  violation := {"resource": resource_address, "message": msg}
}