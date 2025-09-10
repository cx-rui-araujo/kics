package main

__rego_metadata__ := {"id": "KICS-AWS-987","title": "Ensure AWS EC2 Client VPN endpoint enforces client route options","severity": "MEDIUM","description": "Enabling client_route_enforcement_options prevents clients from accessing unintended VPC subnets. Ensure enforce_client_vpn_clients is set to true.","reference_id": "aws-ec2-client-vpn-endpoint-unique","provider": "AWS","service": "EC2ClientVPN","short_code": "client-route-enforce"}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  not resource.change.after.client_route_enforcement_options.enforce_client_vpn_clients
  msg := sprintf("Resource %s should have client_route_enforcement_options.enforce_client_vpn_clients set to true", [resource.address])
}