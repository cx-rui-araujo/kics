package kics

violation[{"msg": msg, "resource": resource.address}] {
  resource := input.resource_changes.aws_ec2_client_vpn_endpoint[_]
  not resource.change.after.client_route_enforcement_options
  msg := "Missing client_route_enforcement_options in aws_ec2_client_vpn_endpoint resource. Route enforcement is disabled, allowing unrestricted client routing."
}