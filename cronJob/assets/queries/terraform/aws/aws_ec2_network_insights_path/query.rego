package main

import data.terraform.tfconfig as tfconfig

violation[{
  "resource": resource.metadata.name,
  "message": msg
}] {
  resource := tfconfig.resource.aws_ec2_network_insights_path[_]
  # Check if filter_at_source block is missing or source_address is unspecified
  not has_valid_source_address(resource)
  msg := sprintf("Resource '%s' must define a filter_at_source block with a non-empty source_address to avoid allowing all traffic.", [resource.metadata.name])
}

# Helper to detect a valid source_address in filter_at_source
has_valid_source_address(resource) {
  some i
  block := resource.block.filter_at_source[i]
  block.source_address
}