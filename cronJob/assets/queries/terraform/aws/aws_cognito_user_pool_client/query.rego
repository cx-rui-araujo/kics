metadata:
  id: "KICS-AWS-COGNITO-001"
  version: "1.0.0"
  title: "Ensure refresh_token_rotation is enabled for AWS Cognito User Pool Client"
  severity: "MEDIUM"
  description: "Enables refresh_token_rotation to mitigate token replay vulnerabilities."
  provider: "aws"
  service: "cognito"
  resource: "aws_cognito_user_pool_client"
---
package main

import data.input.resource_changes as resource_changes

violation[resource] {
  resource := resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  not after.refresh_token_rotation
  resource = {
    "id": resource.address,
    "message": "refresh_token_rotation is not enabled for Cognito User Pool Client"
  }
}