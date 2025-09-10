package kics

denied["aws_ec2_client_vpn_endpoint must define client_route_enforcement_options"] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  not resource.change.after.client_route_enforcement_options
}