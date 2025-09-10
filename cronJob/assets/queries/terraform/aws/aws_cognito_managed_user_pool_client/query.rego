metadata:
  id: KICS-TF-0001
  version: "1.0"
  name: "Ensure refresh_token_rotation is enabled for Cognito User Pool Client"
  severity: "HIGH"
  frameworks:
    - terraform
  resource: aws_cognito_user_pool_client
---
package main

deny[msg] {
  block := input.Blocks[_]
  block.Type == "resource"
  block.Labels[0] == "aws_cognito_user_pool_client"
  attr := block.Attributes.refresh_token_rotation
  attr.Value == false
  msg := "Cognito refresh_token_rotation is disabled; enable it to prevent token replay attacks."
}
