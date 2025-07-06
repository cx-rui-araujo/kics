package aws_client_vpn

import data.terraform.providers as providers

violation[{"msg": msg, "resource_id": resource.address}] {
  resource := input.resource_changes.aws_ec2_client_vpn_endpoint[_]
  after := resource.change.after
  not after.client_route_enforcement_options
  msg := sprintf("Client VPN endpoint %s missing client_route_enforcement_options, allowing unrestricted client-to-client traffic.", [resource.address])
}