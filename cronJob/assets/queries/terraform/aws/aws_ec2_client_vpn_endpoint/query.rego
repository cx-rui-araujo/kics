package kics

violation[resource] {
  resource := input.resources[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  block := resource.configuration.client_route_enforcement_options
  block == null or block[0].enabled == false
}