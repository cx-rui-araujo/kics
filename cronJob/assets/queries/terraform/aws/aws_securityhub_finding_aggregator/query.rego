package terraform

__rego_metadata__ := {
  "id": "KICS-0000",
  "title": "Security Hub Finding Aggregator with NO_REGIONS linking_mode",
  "severity": "LOW",
  "type": "VIOLATION",
  "affected_resource": "aws_securityhub_finding_aggregator",
}

violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
  res := {
    "resource": resource.address,
    "message": "Linking mode 'NO_REGIONS' disables region scanning and may cause missing findings across regions"
  }
}