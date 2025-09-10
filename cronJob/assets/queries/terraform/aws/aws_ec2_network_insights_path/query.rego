package main

violation[{"resource": resource.address, "msg": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_network_insights_path"
  some i
  resource.change.after.filter_at_source[i]
  not resource.change.after.filter_at_source[i].source_address
  msg := "The aws_ec2_network_insights_path resource has unspecified filter_at_source.source_address, which defaults to any IP, potentially allowing all traffic."
}