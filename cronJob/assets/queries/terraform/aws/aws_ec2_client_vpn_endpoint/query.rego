package terraform.aws.security

deny[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  not after.client_route_enforcement_options
  res := {
    "message": "Missing client_route_enforcement_options block allows unrestricted client routing",
    "resource": resource.address
  }
}

deny[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  options := after.client_route_enforcement_options
  options.enforce_all == false
  res := {
    "message": "client_route_enforcement_options.enforce_all set to false disables route enforcement",
    "resource": resource.address
  }
}
