package main

__rego_metadoc__ = {
  "id": "AWS005",
  "version": "1.0.0",
  "title": "Ensure Cognito refresh_token_rotation is enabled",
  "severity": "LOW",
  "type": "terraform"
}

violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  after := resource.change.after
  not after.refresh_token_rotation
  res := {"resource": resource.address}
}