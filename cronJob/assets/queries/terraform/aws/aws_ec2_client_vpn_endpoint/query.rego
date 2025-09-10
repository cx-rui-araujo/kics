package custom

violation[msg] {
  # Find AWS EC2 Client VPN endpoints in Terraform changes
  change := input.resource_changes[_].change
  change.after.type == "aws_ec2_client_vpn_endpoint"
  # Enforce client routes must be explicitly set to true
  change.after.client_route_enforcement_options.enforce_client_routes != true
  msg := "Client VPN endpoint does not enforce client routes, potentially allowing traffic to unintended destinations."
}