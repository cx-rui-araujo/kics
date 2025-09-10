package aws

__rego_metadata__ := {"id":"AWS_NetworkInsights_1","title":"AWS EC2 Network Insights Path filter_at_source.source_address must be specified","severity":"MEDIUM","description":"Ensure filter_at_source.source_address is specified to prevent unfiltered traffic path analysis."}

violation[violationMetadata] {
  input.resource_config.resource_type == "aws_ec2_network_insights_path"
  not input.resource_config.filter_at_source
  violationMetadata := {"msg":"filter_at_source block is missing. This allows unfiltered traffic path analysis.","resource":input.resource_config.name}
}

violation[violationMetadata] {
  input.resource_config.resource_type == "aws_ec2_network_insights_path"
  input.resource_config.filter_at_source.source_address == ""
  violationMetadata := {"msg":"filter_at_source.source_address is empty. This allows unfiltered traffic path analysis.","resource":input.resource_config.name}
}