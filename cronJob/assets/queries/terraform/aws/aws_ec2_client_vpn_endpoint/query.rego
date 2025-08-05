package main

import data.tfconfig.v1 as tfconfig

deny[msg] {
  resource := tfconfig.resource_blocks.aws_ec2_client_vpn_endpoint[_]
  not resource.attributes.client_route_enforcement_options
  msg = "Missing client_route_enforcement_options in aws_ec2_client_vpn_endpoint"
}

deny[msg] {
  resource := tfconfig.resource_blocks.aws_ec2_client_vpn_endpoint[_]
  opts := resource.attributes.client_route_enforcement_options
  opts.0.enforced == false
  msg = "Client route enforcement is disabled in aws_ec2_client_vpn_endpoint"
}