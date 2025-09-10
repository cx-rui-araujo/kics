package main

__rego_metadata__ = {
  "id": "AWS163",
  "title": "Ensure 'filter_at_source.source_address' is specified",
  "description": "A missing or empty source_address in filter_at_source can allow unintended traffic sources to be analyzed, leading to overly broad network insights paths.",
  "severity": "MEDIUM",
  "category": "Misconfiguration",
  "resource_type": "aws_ec2_network_insights_path"
}

deny[message] {
  resource := input.resource_config.aws_ec2_network_insights_path[_]
  # filter_at_source block exists
  resource.filter_at_source
  # no source_address specified or it's empty
  not resource.filter_at_source[_].source_address
  message := sprintf("Resource '%s' has no filter_at_source.source_address specified", [resource.address])
}