package KICS

__rego_metadata__ := {
  "id": "AWS.KCS.K74",
  "version": "1.0",
  "title": "Ensure AWS Client VPN endpoint enforces client route policies",
  "description": "Client VPN endpoint must enable client_route_enforcement_options to prevent unrestricted VPC traffic.",
  "severity": "HIGH",
  "provider": "aws",
  "resource": "aws_ec2_client_vpn_endpoint"
}

denied[msg] {
  input.resource_type == "aws_ec2_client_vpn_endpoint"
  # missing client_route_enforcement_options block
  not input.values.client_route_enforcement_options
  msg = "Missing client_route_enforcement_options: VPN clients may route to unintended VPC subnets."
}

denied[msg] {
  input.resource_type == "aws_ec2_client_vpn_endpoint"
  opts := input.values.client_route_enforcement_options
  opts.enabled == false
  msg = "client_route_enforcement_options.enabled is false: VPN clients may route to unintended subnets."
}