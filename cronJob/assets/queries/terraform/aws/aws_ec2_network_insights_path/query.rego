package main

__rego_metadata__ = {
  "id": "CUSTOM_AWS_EC2_NETWORK_INSIGHTS_PATH_001",
  "title": "Missing filter_at_source.source_address",
  "severity": "HIGH",
  "description": "Ensure aws_ec2_network_insights_path has filter_at_source.source_address specified to avoid unfiltered analysis paths.",
  "resource_types": ["aws_ec2_network_insights_path"]
}

violation[resource] {
  resource := terraform.resources[_]
  resource.type == "aws_ec2_network_insights_path"
  filter := resource.values.filter_at_source
  not filter.source_address
}