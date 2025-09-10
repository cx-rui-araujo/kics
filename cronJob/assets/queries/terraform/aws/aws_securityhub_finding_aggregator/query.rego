package terraform.securityhub

__rego_meta__ := {
  "id": "AWS.0001",
  "title": "Avoid NO_REGIONS in SecurityHub Finding Aggregator",
  "severity": "MEDIUM",
  "platform": "Terraform",
  "description": "Using linking_mode NO_REGIONS may cause missing cross-region findings in the Security Hub Aggregator."
}

deny[msg] {
  resource := input.RootModule.Resources[_]
  resource.Type == "aws_securityhub_finding_aggregator"
  attr := resource.Attributes.linking_mode
  attr.Value == "NO_REGIONS"
  msg := sprintf("Resource '%s' has linking_mode set to NO_REGIONS, which may lead to incomplete findings aggregation.", [resource.Name])
}