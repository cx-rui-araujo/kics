package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  not after.client_route_enforcement_options
  msg := "aws_ec2_client_vpn_endpoint must define client_route_enforcement_options to restrict client routes"
}