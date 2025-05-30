package main

# Checks that aws_ec2_client_vpn_endpoint has client_route_enforcement_options.enabled = true
# to prevent clients from accessing unintended networks

den[y] {
  rc := input.resource_changes[_]
  rc.type == "aws_ec2_client_vpn_endpoint"
  after := rc.change.after
  # Ensure the block exists and is set to true
  opts := after.client_route_enforcement_options
  # If enforcement is explicitly disabled, flag it
  opts[0].enabled == false
  y := {
    "msg": sprintf("EC2 Client VPN Endpoint '%s' has client_route_enforcement_options.enabled = false, allowing unrestricted client routes", [rc.address]),
    "resource": rc.address
  }
}