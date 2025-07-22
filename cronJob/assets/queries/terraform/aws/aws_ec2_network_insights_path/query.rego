package kics

__rego_metadata__ = {"id":"AWS_NIP_001","title":"Missing filter_at_source.source_address in aws_ec2_network_insights_path","severity":"HIGH","type":"terraform"}

violation[resource] {
  resource := tfconfig.resources.aws_ec2_network_insights_path[r]
  filter := resource.config.filter_at_source[0]
  not filter.source_address
  resource.id = r
}