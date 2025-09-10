package kics

import data

metadata := {
  "id": "AWS.SHC_NO_REGIONS_LINKING_MODE",
  "name": "Ensure Security Hub Finding Aggregator linking_mode is not NO_REGIONS",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
  "category": "Security Hub"
}

deny[violation] {
  input.resource.type == "aws_securityhub_finding_aggregator"
  input.resource.values.linking_mode == "NO_REGIONS"
  violation := {
    "message": sprintf("Security Hub aggregator '%v' configured with linking_mode NO_REGIONS leads to incomplete cross-region findings aggregation", [input.resource.name]),
    "metadata": metadata
  }
}
