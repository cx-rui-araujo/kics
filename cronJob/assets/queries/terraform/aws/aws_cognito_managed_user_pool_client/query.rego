package main

__rego_metadata__ := {
  "id": "KICS_TF_AWS_COGNITO_1",
  "title": "Ensure refresh_token_rotation is enabled for AWS Cognito Managed User Pool Client",
  "severity": "MEDIUM",
  "type": "Terraform Security",
  "metadata": {
    "cwe": "CWE-541",
    "references": [
      "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_managed_user_pool_client#refresh_token_rotation"
    ]
  }
}

deny[message] {
  resource := input.resource_blocks[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  refresh_attr := resource.attributes.refresh_token_rotation
  refresh_attr.value == false
  message := sprintf("Resource '%s' has refresh_token_rotation disabled, which may allow reuse of refresh tokens and increase replay attack risk.", [resource.labels[1]])
}