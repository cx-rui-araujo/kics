package terraform.kics.aws_ec2_client_vpn_endpoint

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  enforcement := resource.change.after.client_route_enforcement_options[0]
  enforcement.enabled == false
}