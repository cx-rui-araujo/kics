package main

__rego_metadata__ = {
  "id": "KICS_AWS_CVPN_001",
  "title": "Ensure AWS EC2 Client VPN Endpoint has client_route_enforcement_options enforcement enabled",
  "severity": "HIGH",
  "type": "VIOLATION"
}

deny[{
  "msg": msg,
  "resource": resource.address
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  enforcement := after.client_route_enforcement_options.enforcement_enabled
  enforcement == false
  msg := sprintf("Client route enforcement is disabled on %s, which can allow unauthorized route injection.", [resource.address])
}