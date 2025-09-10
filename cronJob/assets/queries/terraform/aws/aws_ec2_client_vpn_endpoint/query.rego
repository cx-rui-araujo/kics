package main

violation[{"msg": msg, "resource": resource.address}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  after.client_route_enforcement_options != null
  not after.client_route_enforcement_options.enabled
  msg := sprintf("Client VPN endpoint '%s' has route enforcement disabled", [resource.address])
}