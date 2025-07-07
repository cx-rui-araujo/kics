package main

__rego_metadata__ = {
  "id": "AWS_TF_NI_PATH_001",
  "title": "Missing filter_at_source.source_address in Network Insights Path",
  "severity": "MEDIUM",
  "type": "misconfiguration",
}

violation[issue] {
  resource := input.resource
  resource.type == "aws_ec2_network_insights_path"
  # filter_at_source not defined or source_address unset
  (not resource.values.filter_at_source) or resource.values.filter_at_source.source_address == ""
  issue := {
    "message": "filter_at_source.source_address is not specified; unrestricted traffic may be allowed.",
    "resource": resource.address,
  }
}
