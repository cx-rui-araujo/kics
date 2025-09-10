package terraform.aws.security

import input

__rego_metadata__ := {
  "id": "AWS004_CLIENT_ROUTE_ENFORCEMENT",
  "title": "Ensure EC2 Client VPN Endpoint enforces client routes",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

violation[issue] {
  # Iterate over all resource changes
  rc := input.resource_changes[_]
  rc.type == "aws_ec2_client_vpn_endpoint"
  after := rc.change.after
  # If client_route_enforcement_options is present and explicitly disabled or absent
  not after.client_route_enforcement_options.enable
  issue := {
    "message": sprintf(
      "Client VPN endpoint '%s' does not enforce client route restrictions, allowing unrestricted network access.",
      [rc.address]
    ),
    "resource": rc.address
  }
}