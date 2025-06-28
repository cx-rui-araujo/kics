package kics

# KICS Terraform rule to detect missing client_route_enforcement_options on EC2 Client VPN Endpoint
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  not resource.change.after.client_route_enforcement_options
  msg = "Missing client_route_enforcement_options configuration may allow clients unrestricted network access."
}