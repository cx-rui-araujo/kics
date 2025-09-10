package kics

violation[{
  "msg": msg,
  "resource": resource.address,
  "severity": "MEDIUM"
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_network_insights_path"
  after := resource.change.after
  filter := after.filter_at_source
  not filter.source_address
  msg := "The aws_ec2_network_insights_path resource is missing filter_at_source.source_address, which may allow unfiltered traffic and unintended network exposure."
}