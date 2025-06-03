package terraform.aws

__rego_metadata__ = {
  "id": "AWS_COGNITO_001",
  "title": "Cognito user pool client should enable refresh token rotation",
  "description": "Refresh token rotation should be enabled to prevent reuse of stale tokens.",
  "severity": "MEDIUM",
  "category": "Security",
  "resource_type": "aws_cognito_managed_user_pool_client"
}

violation[{"msg": msg, "resource": inst.address}] {
  resource := input.resource_instances[resource_idx]
  resource.type == "aws_cognito_managed_user_pool_client"
  inst := resource.instances[inst_idx]
  not inst.attributes.refresh_token_rotation
  msg := "Refresh token rotation is not enabled, risking token replay attacks."
}