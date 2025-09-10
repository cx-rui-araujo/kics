package main

violation[{"resource": resource.Address, "message": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  not after.client_route_enforcement_options
  msg := "client_route_enforcement_options is not defined, defaulting to no enforcement"
}

violation[{"resource": resource.Address, "message": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  options := resource.change.after.client_route_enforcement_options
  options.enforcement_enabled == false
  msg := "client_route_enforcement_options.enforcement_enabled is false, routes are not enforced"
}