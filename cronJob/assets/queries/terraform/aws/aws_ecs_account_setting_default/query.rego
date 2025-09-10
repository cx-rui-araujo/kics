package aws.ecs

import data.terraform.tfplan as tfplan

__rego_metadata__ := {
  "id": "AWS.ECS.ACCOUNT_SETTING_DEFAULT.001",
  "version": "1.0.0",
  "title": "ECS defaultLogDriverMode should not be non-blocking",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "affected_resource": "aws_ecs_account_setting_default",
  "provider": "aws",
  "service": "ecs",
  "description": "Setting defaultLogDriverMode to non-blocking may drop logs under high load, resulting in loss of audit data.",
  "recommended_actions": "Use 'blocking' mode for defaultLogDriverMode to ensure reliable log delivery."
}

violation[{
  "resource": res.address,
  "message": sprintf("Resource '%s' uses non-blocking log driver mode which may drop logs.", [res.address])
}] {
  res := tfplan.resource_changes[_]
  res.type == "aws_ecs_account_setting_default"
  after := res.change.after
  after.Name == "defaultLogDriverMode"
  after.Value == "non-blocking"
}