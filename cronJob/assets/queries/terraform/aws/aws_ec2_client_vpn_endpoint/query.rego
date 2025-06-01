package main

__rego_metadoc__ = {
  "id": "AWS.CPV.01",
  "title": "Ensure EC2 Client VPN endpoint enforces client route",
  "description": "Without enforcing client routes, unauthorized access to network resources can occur.",
  "severity": "MEDIUM",
  "provider": "AWS",
  "service": "ec2"
}

violation[details] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  action := resource.change.actions[_]
  action != "delete"
  not enforce_option(resource)
  details := {
    "resource": resource.address,
    "message": "client_route_enforcement_options is not set or is disabled"
  }
}

# enforce_option returns true if client_route_enforcement_options is defined and enabled
enforce_option(resource) {
  opts := resource.change.after.client_route_enforcement_options
  count(opts) > 0
  opts[0].enabled
}