package terraform.aws.EC2NetworkInsightsPath

# Violation if aws_ec2_network_insights_path.filter_at_source is defined but source_address is missing
violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_network_insights_path"
  resource.change.after.filter_at_source
  not resource.change.after.filter_at_source.source_address
}