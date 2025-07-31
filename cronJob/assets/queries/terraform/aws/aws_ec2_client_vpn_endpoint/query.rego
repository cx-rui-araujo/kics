package terraform.aws.ec2_client_vpn_endpoint

default allow = false

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  # Imaginary vulnerability: missing or misconfigured route enforcement allows clients to reach unintended network ranges
  not after.client_route_enforcement_options
  msg := sprintf("EC2 Client VPN endpoint '%s' has no client_route_enforcement_options block; route enforcement not configured, may allow unrestricted client network access.", [resource.address])
}