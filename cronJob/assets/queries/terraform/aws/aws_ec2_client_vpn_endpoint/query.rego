package main

import data

violation[issue] {
  resources := input.planned_values.root_module.resources
  resource := resources[_]
  resource.resource_type == "aws_ec2_client_vpn_endpoint"
  opts := resource.values.client_route_enforcement_options
  # If enforcement options are not set or explicitly disabled, clients may bypass routing rules
  (opts == null) || (opts.enabled == false)
  issue := {
    "message": "Ensure client_route_enforcement_options is enabled to enforce VPN routing and prevent client bypass.",
    "resource": resource.address
  }
}