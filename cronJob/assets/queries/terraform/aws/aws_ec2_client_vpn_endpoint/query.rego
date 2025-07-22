package terraform.aws.client_vpn

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  opts := after.client_route_enforcement_options
  opts.enforce == false
  msg := sprintf("Client VPN endpoint '%s' has route enforcement disabled", [resource.address])
}