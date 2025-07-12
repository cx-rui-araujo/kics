package tf_aws_network_insights

__rego_metadata__ = {
  "id": "AWS9999",
  "title": "Ensure filter_at_source.source_address is specified",
  "severity": "HIGH",
  "type": "BUG_RISK",
  "description": "Detects aws_ec2_network_insights_path resources where filter_at_source.source_address is not specified, which may allow unfiltered traffic to bypass inspection."
}

violation[resource] {
  resource := input.resource
  resource.Type == "aws_ec2_network_insights_path"
  filter := resource.Config.filter_at_source
  filter != null
  not filter.source_address
}