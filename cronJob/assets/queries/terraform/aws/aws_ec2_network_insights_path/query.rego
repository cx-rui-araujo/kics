package terraform.security.aws

denial[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_network_insights_path"
  after := resource.change.after
  after.filter_at_source
  not after.filter_at_source.source_address
  msg := sprintf("The aws_ec2_network_insights_path '%s' has filter_at_source.source_address unspecified, which may lead to unfiltered path analysis.", [resource.address])
}