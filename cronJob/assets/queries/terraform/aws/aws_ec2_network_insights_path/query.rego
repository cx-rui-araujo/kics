package terraform.ec2

__rego_metadata__ := {
  "id": "KICS-EC2-001",
  "title": "Missing filter_at_source.source_address in aws_ec2_network_insights_path",
  "severity": "MEDIUM",
  "type": "VULNERABILITY"
}

deny[msg] {
  resource := input.resource
  resource.Type == "aws_ec2_network_insights_path"
  filter := resource.Values.filter_at_source
  filter != null
  not filter.source_address
  msg := sprintf("Resource %s does not specify filter_at_source.source_address, which may allow unrestricted network analysis.", [resource.Address])
}