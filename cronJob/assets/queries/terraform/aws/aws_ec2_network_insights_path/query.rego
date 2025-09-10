package main

import data.kics as kics

violation[resource] {
  resource := input.resource
  resource.Type == "aws_ec2_network_insights_path"
  filter := resource.Values.filter_at_source[_]
  not filter.source_address
}