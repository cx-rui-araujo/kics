package main

# Deny if client_route_enforcement_options block is missing or not enforcing routes
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  # Either missing or not enabled
  not after.client_route_enforcement_options
  msg = "Missing client_route_enforcement_options; this may allow unrestricted client VPN routing."
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  opts := after.client_route_enforcement_options
  opts.enabled != true
  msg = "client_route_enforcement_options.enabled should be set to true to enforce client route restrictions."
}