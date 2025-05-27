package terraform.aws

__rego_metadata__ := {
  "id": "KICS_AWS_0001",
  "title": "Ensure AWS EC2 Client VPN Endpoint has route enforcement enabled",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "category": "Networking",
  "resource": "aws_ec2_client_vpn_endpoint"
}

violation[endpoint] {
  endpoint := input.resource_changes[_]
  endpoint.type == "aws_ec2_client_vpn_endpoint"
  after := endpoint.change.after
  # If client_route_enforcement_options is missing or enforce is set to false, it's insecure
  missing := not after.client_route_enforcement_options
  disabled := after.client_route_enforcement_options.enforce == false
  missing or disabled
}