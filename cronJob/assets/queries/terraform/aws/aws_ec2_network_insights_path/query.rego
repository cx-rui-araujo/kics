package terraform.aws.NetworkInsightsPath

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_network_insights_path"
  after := resource.change.after
  after.filter_at_source != null
  not after.filter_at_source.source_address
}