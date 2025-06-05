package main

__rego_metadata__ := {
  "id": "KICS-AWS-EC2-NIP-001",
  "title": "AWS EC2 Network Insights Path missing source_address filter",
  "severity": "MEDIUM",
  "type": "VIOLATION"
}

violation[{
  "msg": msg,
  "resource": res.address
}] {
  input.kind == "terraform"
  res := input.resource_changes[_]
  res.type == "aws_ec2_network_insights_path"
  after := res.change.after
  filter := after.filter_at_source
  filter
  not filter.source_address
  msg := sprintf("Resource '%s' uses filter_at_source without specifying source_address, allowing all source traffic.", [res.address])
}