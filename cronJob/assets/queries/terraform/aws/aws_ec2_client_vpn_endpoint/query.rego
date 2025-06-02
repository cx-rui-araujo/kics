package main

# Ensure client_route_enforcement_options.enforce_client_routes is enabled to prevent unauthorized routing
violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  # If client_route_enforcement_options is defined and enforce_client_routes is false or missing
  enforcement := after.client_route_enforcement_options
  enforcement
  not enforcement.enforce_client_routes
  resource
}