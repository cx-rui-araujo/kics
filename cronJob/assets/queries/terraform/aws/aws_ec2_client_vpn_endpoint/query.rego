package terraform.aws_ec2_client_vpn_endpoint

__rego_metadata__ = {
  "id": "AWS_EC2_CLIENT_VPN_ROUTE_ENFORCEMENT",
  "title": "Ensure AWS EC2 Client VPN Endpoint enforces client routes",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "uri": "https://docs.kics.io/latest/queries/terraform/aws/ec2_client_vpn_route_enforcement"
}

deny[msg] {
  rc := input.resource_changes[_]
  rc.type == "aws_ec2_client_vpn_endpoint"
  after := rc.change.after
  # Missing enforcement options entirely
  not after.client_route_enforcement_options
  msg = sprintf("%s does not configure client_route_enforcement_options, risking unauthorized route access", [rc.address])
}

deny[msg] {
  rc := input.resource_changes[_]
  rc.type == "aws_ec2_client_vpn_endpoint"
  opts := rc.change.after.client_route_enforcement_options[0]
  # Explicitly disabling enforcement
  opts.enforce == false
  msg = sprintf("%s sets client_route_enforcement_options.enforce to false, allowing insecure client routing", [rc.address])
}