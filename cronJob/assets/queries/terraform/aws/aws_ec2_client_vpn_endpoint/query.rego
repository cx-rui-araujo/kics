package main

__rego_metadata__ = {
  "id": "AWS_CLIENT_VPN_ROUTE_ENFORCEMENT",
  "title": "Ensure EC2 Client VPN endpoint enforces client routes",
  "severity": "HIGH"
}

violation[{
  "resource": resource.address,
  "msg": msg
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  opts := after.client_route_enforcement_options
  opts[0].enabled == false
  msg := sprintf("EC2 Client VPN endpoint '%s' has client_route_enforcement_options.enabled set to false, allowing clients to access unauthorized networks", [resource.address])
}