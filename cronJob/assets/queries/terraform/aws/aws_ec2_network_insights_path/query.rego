package main

__rego_metadata__ := {
  "id": "AWS_NW_INSIGHTS_PATH_SOURCE_ADDRESS",
  "title": "Ensure aws_ec2_network_insights_path has filter_at_source.source_address",
  "severity": "HIGH",
  "type": "Misconfiguration",
  "provider": "aws",
}

violation[output] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_network_insights_path"
  after := resource.change.after
  # No source_address defined on filter_at_source
  after.filter_at_source
  not after.filter_at_source.source_address

  output := {
    "message": sprintf("Resource '%s' has no filter_at_source.source_address defined", [resource.address]),
    "resource": resource.address
  }
}