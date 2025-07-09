package main

denY[msg] {
  input.resource_changes[_] = rc
  rc.type == "aws_ec2_network_insights_path"
  after := rc.change.after
  after.filter_at_source
  not after.filter_at_source.source_address
  msg := "Missing filter_at_source.source_address in aws_ec2_network_insights_path, allowing unintended traffic."
}