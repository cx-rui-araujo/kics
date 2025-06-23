package main

# Deny if client_route_enforcement_options is missing or disabled on AWS EC2 Client VPN Endpoint

deny[res] {
  res := input.Resources[_]
  res.Type == "aws_ec2_client_vpn_endpoint"

  # Block is missing entirely
  not res.Values.client_route_enforcement_options
}

deny[res] {
  res := input.Resources[_]
  res.Type == "aws_ec2_client_vpn_endpoint"

  # Block exists but 'enabled' is false
  opts := res.Values.client_route_enforcement_options
  opts[0].enabled == false
}