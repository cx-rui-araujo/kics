package main

__rego_metadata__ := {
  "id": "KICS-42430",
  "title": "AWS Cognito User Pool Client should enable refresh_token_rotation",
  "severity": "LOW"
}

violation[resource] {
  resource := input.Blocks[_]
  resource.Type == "resource"
  resource.Labels[0] == "aws_cognito_user_pool_client"
  attr := resource.Body.Attributes.refresh_token_rotation
  (attr == null) || (attr.Value == false)
}