package terraform.client_vpn

violation[{"msg": msg, "resource": resource_name}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  opts := after.client_route_enforcement_options
  some i
  opts[i].enforce_client_route == false
  resource_name := resource.address
  msg := sprintf("Client route enforcement is disabled for %s, which may allow clients to bypass network policies", [resource_name])
}