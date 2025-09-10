package terraform.aws

__rego_metadoc__ := {
  "id": "AWS_FilterAtSource_SourceAddress_Missing",
  "title": "Ensure explicit source_address in filter_at_source for aws_ec2_network_insights_path",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "description": "When filter_at_source.source_address is unspecified, the insights path may analyze unintended traffic, potentially leading to misconfigurations or unauthorized network access.",
  "reference_id": "AWS-123",
  "supported_resources": ["aws_ec2_network_insights_path"]
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_network_insights_path"
  after := resource.change.after
  filter := after.filter_at_source
  not filter.source_address
  msg := sprintf("Resource '%s' does not specify filter_at_source.source_address", [resource.address])
}
