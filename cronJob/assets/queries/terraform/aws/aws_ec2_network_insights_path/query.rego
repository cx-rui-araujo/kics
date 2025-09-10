package main

# Detect aws_ec2_network_insights_path missing filter_at_source.source_address
violation[resource] {
  resource := input.resource[_]
  resource.type == "aws_ec2_network_insights_path"
  # Either filter_at_source block is missing entirely or source_address is not set
  (resource.filter_at_source == null) || not resource.filter_at_source.source_address
  msg := sprintf("Resource '%s' should specify filter_at_source.source_address to avoid unintended path analysis", [resource.name])
}