package aws

violation[{"msg": msg, "resource": address}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_network_insights_path"
  address := resource.address
  after := resource.change.after
  not after.filter_at_source.source_address
  msg := sprintf("Missing 'filter_at_source.source_address' in resource %s may allow unintended traffic path analysis by attackers", [address])
}