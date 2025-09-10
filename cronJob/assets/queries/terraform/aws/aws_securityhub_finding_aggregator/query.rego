package kics

import data.tfplan as plan

violation[{
  "rule_id": "KICS-AWS-001",
  "resource": res.address,
  "message": "Security Hub Finding Aggregator 'linking_mode' is set to NO_REGIONS, disabling cross-region aggregation."
}] {
  res := plan.resource_changes[_]
  res.type == "aws_securityhub_finding_aggregator"
  res.change.after.linking_mode == "NO_REGIONS"
}