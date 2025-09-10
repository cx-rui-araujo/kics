package kics

import data.tfconfig

violation[{{"msg": msg}}] {
  resource := tfconfig.resource[resourceKey]
  resource.type == "aws_ec2_client_vpn_endpoint"
  not resource.values.client_route_enforcement_options
  msg := "Client VPN endpoint missing client_route_enforcement_options, allowing clients to override VPN routes."
}

violation[{{"msg": msg}}] {
  resource := tfconfig.resource[resourceKey]
  resource.type == "aws_ec2_client_vpn_endpoint"
  options := resource.values.client_route_enforcement_options[0]
  options.enabled == false
  msg := "client_route_enforcement_options.enabled is false, allowing clients to override VPN routes."
}