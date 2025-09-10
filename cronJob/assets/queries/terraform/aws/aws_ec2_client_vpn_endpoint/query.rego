package kics

# KICS rule: Ensure client route enforcement is enabled on EC2 Client VPN endpoints
# Ref: aws_ec2_client_vpn_endpoint.client_route_enforcement_options

deny[msg] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  # If enforcement_enabled is explicitly set to false or omitted (default false)
  not after.client_route_enforcement_options.enforcement_enabled
  msg := sprintf("Client route enforcement is disabled for VPN endpoint '%s'", [resource.address])
}