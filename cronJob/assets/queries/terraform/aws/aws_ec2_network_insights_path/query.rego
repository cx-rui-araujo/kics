package main

import "tfconfig"

violation[resource] {
  resource := tfconfig.Modules().Resources[addr]
  resource.Type == "aws_ec2_network_insights_path"
  not resource.Values.filter_at_source.source_address
}
