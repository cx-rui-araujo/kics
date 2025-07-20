package aws_client_vpn

__rego_metadata__ = {
  "id": "AWS_VPN_001",
  "title": "Ensure client route enforcement is enabled",
  "severity": "HIGH",
  "type": "terraform",
  "description": "Ensure client_route_enforcement_options is enabled to enforce only defined routes and prevent unauthorized access."
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  not after.client_route_enforcement_options
  msg := sprintf("Client route enforcement options missing for %s", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  opts := after.client_route_enforcement_options[0]
  opts.enabled == false
  msg := sprintf("Client route enforcement is disabled for %s", [resource.address])
}