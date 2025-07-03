package main

import data.terraform

__rego_metadata__ = {
  "id": "KICS-9999",
  "title": "Missing 'filter_at_source.source_address' in AWS EC2 Network Insights Path",
  "severity": "MEDIUM",
  "type": "VIOLATION",
  "supported_resources": ["aws_ec2_network_insights_path"],
  "confidence": "HIGH"
}

violation[resource] {
  resource := terraform.aws_ec2_network_insights_path[_]
  filter := resource.values.filter_at_source
  not filter.source_address
}