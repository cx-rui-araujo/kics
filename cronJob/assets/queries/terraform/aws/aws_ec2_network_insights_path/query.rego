package findings

__rego_metadata__ = {
  "id": "AWS035",
  "title": "EC2 Network Insights Path without source_address",
  "severity": "HIGH",
  "type": "MISCONFIGURATION"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_network_insights_path"
  after := resource.change.after
  filter := after.filter_at_source[0]
  not filter.source_address
}
