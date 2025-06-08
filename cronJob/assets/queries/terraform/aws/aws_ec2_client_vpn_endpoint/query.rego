package terraform.security.aws

__rego_metadata__
id = \"AWS.VPN.001\"
title = \"Ensure EC2 Client VPN endpoints enforce client routes\"
severity = \"HIGH\"
category = \"Networking\"

violation[{\"msg\": msg}] {
  resource := input.resource_changes[_]
  resource.type == \"aws_ec2_client_vpn_endpoint\"
  opts := resource.change.after.client_route_enforcement_options[0]
  opts.enforcement_enabled == false
  msg := sprintf(\"Resource '%v' disables client route enforcement, allowing clients to override routes to potentially gain unauthorized access\", [resource.address])
}