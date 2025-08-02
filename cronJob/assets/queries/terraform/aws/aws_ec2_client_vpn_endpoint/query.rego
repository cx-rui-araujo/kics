package terraform.aws.EC2ClientVPNClientRouteEnforcement

__rego_metadata__ := {
  "id": "AWS_EC2_CLIENT_VPN_ENFORCEMENT",
  "title": "Ensure client route enforcement is enabled for AWS EC2 Client VPN Endpoints",
  "description": "Enabling client route enforcement restricts clients to specified network routes and prevents unauthorized access through the VPN endpoint.",
  "severity": "MEDIUM",
  "type": "VIOLATION"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  not after.client_route_enforcement_options
  msg := sprintf("Client route enforcement is not defined for VPN endpoint '%s', defaulting to disabled.", [after.id])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  opts := after.client_route_enforcement_options
  opts.enabled == false
  msg := sprintf("Client route enforcement is disabled for VPN endpoint '%s'.", [after.id])
}
