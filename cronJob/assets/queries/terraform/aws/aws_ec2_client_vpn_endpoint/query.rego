package kics

violation[output] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after.client_route_enforcement_options
  length(after) > 0
  not after[0].enabled
  output := {"resource": resource.address, "msg": "Client route enforcement is disabled on EC2 Client VPN endpoint, potentially allowing clients unrestricted access."}
}