package main

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  opts := resource.change.after.client_route_enforcement_options
  opts.enabled == false
}