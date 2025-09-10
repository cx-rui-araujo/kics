package main

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_network_insights_path"
  not resource.change.after.filter_at_source.source_address
  resource
}