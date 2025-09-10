package terraform

deny[rule] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  # Flag if client_route_enforcement_options is missing or enforcement disabled
  (not after.client_route_enforcement_options) or after.client_route_enforcement_options[0].enforce_routes == false
  rule := {
    "resource": resource.address,
    "msg": sprintf("EC2 Client VPN Endpoint '%s' has insecure client_route_enforcement_options configuration: route enforcement not enabled", [resource.address])
  }
}