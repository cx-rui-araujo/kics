package main

__rego_meta__ := {
  "id": "KICS_AWS_CLIENT_VPN_ROUTE_ENFORCEMENT",
  "title": "EC2 Client VPN endpoint must enforce incoming client routes",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "platform": "Terraform"
}

violation[{"resource": resource.address, "message": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  cfg := resource.change.after
  # Missing client_route_enforcement_options entirely
  not cfg.client_route_enforcement_options
  msg := "Client VPN endpoint does not define route enforcement options, allowing unauthorized routes."
}

violation[{"resource": resource.address, "message": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  cfg := resource.change.after
  opts := cfg.client_route_enforcement_options[0]
  # Policy type should be DROP_INCOMING_CLIENT_ROUTES
  opts.policy_type != "DROP_INCOMING_CLIENT_ROUTES"
  msg := sprintf("Client VPN endpoint policy_type is %v, should be DROP_INCOMING_CLIENT_ROUTES", [opts.policy_type])
}