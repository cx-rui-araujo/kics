package main

__rego_metadata__ = {
  "id": "KICS-AWS-1234",
  "title": "Ensure refresh_token_rotation is enabled on Cognito User Pool Client",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
}

denied[message] {
  input.kind == "terraform.plan"
  resource := input.planned_values.root_module.resources[_]
  resource.type == "aws_cognito_user_pool_client"
  # If refresh_token_rotation is missing or explicitly set to false
  not resource.values.refresh_token_rotation
  message := sprintf("Cognito User Pool Client '%s' does not have refresh_token_rotation enabled.", [resource.address])
}