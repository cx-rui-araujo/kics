package aws

__rego_metadata__ := {
  "id": "AWS_NET_INSIGHTS_PATH_1",
  "title": "Ensure filter_at_source.source_address is specified",
  "severity": "HIGH",
  "category": "Security Best Practices"
}

violation[{"msg": msg, "resource": resource.Address}] {
  resource_block := tfconfig.resource_blocks["aws_ec2_network_insights_path"][resource_name]
  resource_name := resource_block.Name
  not resource_block.HasChild("filter_at_source.source_address")
  msg := sprintf("Resource '%s' missing filter_at_source.source_address, allowing any source address", [resource_block.Address])
}
