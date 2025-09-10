package aws_ec2_network_insights_path_filter_at_source

__rego_metadata__ := {
  "id": "AWS_TF_VULN_001",
  "title": "Ensure filter_at_source.source_address is specified on aws_ec2_network_insights_path",
  "severity": "HIGH",
  "type": "Vulnerability",
  "description": "If filter_at_source.source_address is unspecified, an unrestricted network insights path may be created allowing unintended traffic paths."
}

deny[resp] {
  resource := input.resource
  resource.type == "aws_ec2_network_insights_path"
  not resource.values.filter_at_source.source_address
  resp := {
    "ResourceName": resource.name,
    "Message": "filter_at_source.source_address should be specified to prevent unrestricted network insights path"
  }
}