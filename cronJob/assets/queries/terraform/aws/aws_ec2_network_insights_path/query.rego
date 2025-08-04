package terraform.aws.NetworkInsightsPath

import data.tfconfig as tfcfg

__rego_metadata__ := {
  "id": "CUSTOM_AWS_001",
  "title": "Ensure filter_at_source.source_address is specified for aws_ec2_network_insights_path",
  "severity": "HIGH",
  "category": "Network Security"
}

deny[{
  "msg": msg,
  "resource": name
}] {
  name := resource_name
  resource := tfcfg.resource["aws_ec2_network_insights_path"][name]
  filter := resource.values.filter_at_source
  not filter.source_address
  msg := sprintf("Resource '%s' has unspecified filter_at_source.source_address, allowing unrestricted traffic.", [name])
}