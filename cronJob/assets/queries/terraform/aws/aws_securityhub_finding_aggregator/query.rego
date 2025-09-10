package main

import data.terraform.tfplan as tfplan

denied[message] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
  message := sprintf("Security Hub finding aggregator '%s' uses linking_mode NO_REGIONS, disabling all region aggregation", [resource.address])
}