package main

default allow = false

violation[{
  "msg": msg,
  "resource_id": resource.address
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  after := resource.change.after
  after.linking_mode == "NO_REGIONS"
  msg := sprintf("Resource '%s' uses linking_mode=NO_REGIONS, potentially disabling cross-region findings aggregation", [resource.address])
}