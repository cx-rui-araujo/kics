package terraform.aws.ec2

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  (after.client_route_enforcement_options == null
   or after.client_route_enforcement_options[0].enable_cross_vpc_routing == false)
  msg := sprintf("Client VPN endpoint %s does not enforce client route options, allow cross VPC routing", [resource.address])
}