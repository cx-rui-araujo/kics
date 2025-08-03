package main

import data.tfplan as tfplan

violation[issue] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
  issue := {
    "msg": sprintf("Security Hub finding aggregator '%s' is configured with linking_mode NO_REGIONS, disabling cross-region aggregation.", [resource.address]),
    "resource": resource.address
  }
}