package terraform.aws

__rego_metadata__ = {
  "id": "KICS-1000",
  "title": "Ensure AWS EC2 Client VPN endpoint client route enforcement is enabled",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  not resource.change.after.client_route_enforcement_options
  msg = "EC2 Client VPN endpoint has client route enforcement not configured or disabled"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  opts := resource.change.after.client_route_enforcement_options
  opts[0].enabled == false
  msg = "EC2 Client VPN endpoint client route enforcement is disabled"
}