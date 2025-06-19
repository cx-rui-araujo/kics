package terraform.aws

__rego_metadata__ := {
  "id": "AWS014",
  "title": "AWS Cognito User Pool Client Refresh Token Rotation must be enabled",
  "severity": "HIGH",
  "type": "VIOLATION",
  "platform": "Terraform",
  "categories": ["security"]
}

denied[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  after.refresh_token_rotation == false
  msg := sprintf("Cognito user pool client '%s' has refresh_token_rotation disabled", [resource.address])
}