package kics

// Deny if client_route_enforcement_options.policy_enforcement is set to OPTIONAL
deny[msg] {
  resource := input.resource.aws_ec2_client_vpn_endpoint[_]
  opts := resource.values.client_route_enforcement_options[_]
  opts.policy_enforcement == "OPTIONAL"
  msg := sprintf("Client VPN endpoint '%s' has policy_enforcement set to OPTIONAL, which may allow clients to bypass enforced routes.", [resource.name])
}