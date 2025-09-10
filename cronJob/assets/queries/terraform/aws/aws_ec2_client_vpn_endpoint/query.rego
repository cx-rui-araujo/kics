package aws
import data.terraform.tfconfig as tfconfig

denied[message] {
  resource := tfconfig.resource.aws_ec2_client_vpn_endpoint[resource_name]
  opts := resource.values.client_route_enforcement_options
  not opts.enabled
  message := sprintf("Client VPN endpoint '%s' has client_route_enforcement_options disabled or not set, exposing internal networks to unmanaged routes", [resource_name])
}