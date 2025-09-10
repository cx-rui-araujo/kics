package securityhub

__rego_metadata__ = {
  "id": "KICS-AWS-SH-001",
  "title": "NO_REGIONS linking_mode should not be used for aws_securityhub_finding_aggregator",
  "severity": "MEDIUM",
  "type": "VIOLATION",
  "description": "Using NO_REGIONS as the linking_mode can cause findings to be omitted for many regions, leading to blind spots in Security Hub aggregation."
}

violation[{
  "msg": msg,
  "resource": resource.address
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  after := resource.change.after
  after.linking_mode == "NO_REGIONS"
  msg := sprintf("Resource '%s' uses linking_mode = NO_REGIONS, which may omit region findings.", [resource.address])
}