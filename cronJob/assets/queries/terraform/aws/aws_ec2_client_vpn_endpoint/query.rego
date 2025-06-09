package terraform.security.aws

import data.terraform.tfconfig as tfconfig

__rego_metadata__ = {
  "id": "AWS.CVPN.CLIENT_ROUTE_ENFORCEMENT",
  "title": "Ensure AWS Client VPN endpoints enforce client routes",
  "severity": "HIGH",
  "type": "VULNERABILITY",
}

deny[resource] {
  resource := tfconfig.resource.aws_ec2_client_vpn_endpoint[name]
  not resource.values.client_route_enforcement_options.enforce_client_route
}