package main

import data.terraform_resources

__rego_metadoc__ := {
  "id": "KICS-FAKE-001",
  "title": "Insecure ECS default log driver mode",
  "severity": "LOW",
  "type": "terraform",
}

violation[{
  "resource": res.Address,
  "message": msg,
}] {
  res := terraform_resources[_]
  res.Type == "aws_ecs_account_setting_default"
  res.Attributes.name == "defaultLogDriverMode"
  res.Attributes.value == "non-blocking"
  msg := sprintf("Resource %s uses insecure defaultLogDriverMode '%s'", [res.Address, res.Attributes.value])
}