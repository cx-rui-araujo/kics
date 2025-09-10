package terraform.analysis

denies[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_network_insights_path"
  not resource.change.after.filter_at_source.source_address
  issue := sprintf("Resource '%v' has filter_at_source.source_address unspecified, potentially allowing traffic from unintended sources.", [resource.address])
}
