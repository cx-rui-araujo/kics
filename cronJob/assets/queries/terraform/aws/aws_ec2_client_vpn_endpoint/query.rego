package terraform.aws.security

define_bad_client_route_enforcement[msg] {
  resource := tfconfig.resource.aws_ec2_client_vpn_endpoint[res_name]
  # If the client_route_enforcement_options block is missing or enforcement_enabled is false
  not resource.values.client_route_enforcement_options
  msg := sprintf("VPN endpoint '%s' has no client_route_enforcement_options, clients may bypass route enforcement", [res_name])
}

define_bad_client_route_enforcement[msg] {
  resource := tfconfig.resource.aws_ec2_client_vpn_endpoint[res_name]
  opts := resource.values.client_route_enforcement_options[0]
  not opts.enforcement_enabled
  msg := sprintf("VPN endpoint '%s' has client_route_enforcement_options.enforcement_enabled set to false, clients may bypass route enforcement", [res_name])
}