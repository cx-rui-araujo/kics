package main

__rego_metadata__ := {"id": "KICS_AWS_42424","title": "AWS EC2 Client VPN missing or disabling client route enforcement","severity": "HIGH","type": "VULNERABILITY"}

violation[res] {
  rc := input.resource_changes[_]
  rc.type == "aws_ec2_client_vpn_endpoint"
  after := rc.change.after
  not after.client_route_enforcement_options.enabled
  res := {"ResourceAddr": rc.address}
}
