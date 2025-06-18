package terraform.aws.cognito

__rego_metadata__ := {
  "id": "KICS_AWS_COGNITO_1",
  "title": "Enable refresh_token_rotation for Cognito User Pool Client",
  "severity": "HIGH",
  "type": "VIOLATION"
}

violation[{
  "msg": msg,
  "resource": resource.Address
}] {
  resource := input.Change.PlannedValues.root_module.resources[_]
  resource.Type == "aws_cognito_managed_user_pool_client"
  not resource.Values.refresh_token_rotation
  msg := sprintf("Resource '%s' has refresh_token_rotation disabled. This can lead to token replay vulnerabilities.", [resource.Address])
}