package main

__rego_metadata__ := {
  "id": "TF-AWS-0950",
  "title": "Ensure refresh token rotation is enabled for Cognito user pool clients",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
  "metadata": {"cwe": "CWE-639", "category": "authentication"}
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  not resource.change.after.refresh_token_rotation
}