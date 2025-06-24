package terraform.aws.Cognito

__rego_metadata__ := {
  "id": "AWS040",
  "title": "Ensure refresh_token_rotation is enabled on cognito user pool client",
  "severity": "HIGH",
  "type": "Terraform Security Check",
  "category": "Security Best Practices",
  "description": "Disabling refresh_token_rotation allows reuse of refresh tokens and increases risk if tokens are compromised.",
  "reference_id": "AWS.Cognito.040"
}

violation[resource] {
  resource := input.resource.aws_cognito_user_pool_client[_]
  resource.values.refresh_token_rotation == false
}