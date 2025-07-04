package kics

import data.tfconfig as tfconfig

__rego_metadata__ := {"id": "AWS_CLIENT_VPN_STRICT_ROUTE_ENFORCEMENT","title": "AWS EC2 Client VPN endpoint should enforce strict client route options","severity": "HIGH","type": "VIOLATION"}

violation[resource] {
  resource := tfconfig.resource.blocks[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  not (resource.block.has_key("client_route_enforcement_options")
       and resource.block.client_route_enforcement_options.enforcement_mode == "strict")
}