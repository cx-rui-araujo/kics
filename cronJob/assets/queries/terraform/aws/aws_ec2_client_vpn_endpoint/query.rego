package main

__rego_metadata__ := {"id":"AWS001","title":"Ensure VPN client route enforcement is enabled","description":"Checks if aws_ec2_client_vpn_endpoint.client_route_enforcement_options are properly enforced","severity":"HIGH"}

deny[msg] {
  input.resource_changes[_].type == "aws_ec2_client_vpn_endpoint"
  opts := input.resource_changes[_].change.after.client_route_enforcement_options
  not opts.enabled
  msg = "Client route enforcement is disabled."
}

deny[msg] {
  input.resource_changes[_].type == "aws_ec2_client_vpn_endpoint"
  opts := input.resource_changes[_].change.after.client_route_enforcement_options
  not opts.customized_client_route
  msg = "Customized client route option is disabled."
}