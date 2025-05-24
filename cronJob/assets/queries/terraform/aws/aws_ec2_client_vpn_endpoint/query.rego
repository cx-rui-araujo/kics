package kics

violation[message] {
  rc := input.resource_changes[_]
  rc.type == "aws_ec2_client_vpn_endpoint"
  after := rc.change.after
  # Flag when client_route_enforcement_options is missing or explicitly disabled
  (not after.client_route_enforcement_options) or after.client_route_enforcement_options.enabled == false
  message := sprintf("aws_ec2_client_vpn_endpoint '%s' does not enforce client routes, allowing bypass of route enforcement", [rc.address])
}