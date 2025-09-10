package main

__rego_metadata__ = {
  "id": "AWSKICS-EC2-NET-INSIGHTS-PATH-001",
  "title": "aws_ec2_network_insights_path missing filter_at_source.source_address",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
  "version": "1.0.0",
  "supported_types": ["terraform"],
  "supported_resources": ["aws_ec2_network_insights_path"],
  "description": "Ensure filter_at_source.source_address is specified in aws_ec2_network_insights_path to avoid unfiltered network insights paths."
}

deny[msg] {
  resource := input.resource_blocks[_]
  resource.type == "aws_ec2_network_insights_path"
  # find filter_at_source blocks
  filters := resource.block.filter_at_source
  count(filters) > 0
  # check missing or empty source_address
  filters[_].source_address == ""
  msg := sprintf("Resource '%s' has an unspecified filter_at_source.source_address", [resource.name])
}