# Detect aws_ec2_network_insights_path resources missing a filter_at_source.source_address, which may allow unfiltered traffic sources leading to overly broad network exposure.
package kics

terraform_aws_ec2_network_insights_path_missing_source_address[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_network_insights_path"
  after := resource.change.after
  # source_address unspecified or null
  after.filter_at_source.source_address == null
  msg := sprintf("Resource '%s' missing filter_at_source.source_address", [resource.address])
}
