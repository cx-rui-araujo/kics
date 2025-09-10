package main

__rego_meta__ := {
  "id": "AWS_NetworkInsightsPath_SourceFilter",
  "version": "1.0",
  "title": "Network Insights Path should specify source_address filter",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

deny[res] {
  res := input.resource[_]
  res.type == "aws_ec2_network_insights_path"
  filter := res.config.filter_at_source
  not filter[0].source_address
}