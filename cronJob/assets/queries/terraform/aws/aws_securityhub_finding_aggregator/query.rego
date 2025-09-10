package main

__rego_metadata__ = {
  "id": "TERRAFORM_AWS_SSHUB_001",
  "title": "Avoid using NO_REGIONS in aws_securityhub_finding_aggregator linking_mode",
  "severity": "HIGH",
  "type": "Terraform Security Check",
  "tags": ["aws","securityhub","aggregation"]
}

violations[{
  "msg": msg,
  "resource": resource_address
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  mode := resource.change.after.linking_mode
  mode == "NO_REGIONS"
  resource_address := sprintf("%s.%s", [resource.module_address, resource.name])
  msg := sprintf("Resource %s uses linking_mode 'NO_REGIONS', disabling multi-region aggregation and potentially missing findings", [resource_address])
}