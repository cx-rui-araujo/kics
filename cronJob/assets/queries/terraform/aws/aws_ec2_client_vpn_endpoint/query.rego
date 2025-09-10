package main

__rego_metadata__ := {
  "id": "KICS-AWS-0001",
  "title": "Ensure EC2 Client VPN endpoint enforces client routes",
  "severity": "HIGH",
  "type": "Misconfiguration"
}

deny[message] {
  resource := input.resource.aws_ec2_client_vpn_endpoint[_]
  # Missing enforcement block
  not resource.client_route_enforcement_options
  message := sprintf("EC2 Client VPN endpoint '%s' does not have client route enforcement enabled", [resource.__address__])
}

deny[message] {
  resource := input.resource.aws_ec2_client_vpn_endpoint[_]
  opts := resource.client_route_enforcement_options[_]
  # Enforcement explicitly disabled
  opts.enabled == false
  message := sprintf("EC2 Client VPN endpoint '%s' has client route enforcement disabled", [resource.__address__])
}