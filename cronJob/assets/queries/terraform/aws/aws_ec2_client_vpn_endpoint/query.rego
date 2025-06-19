package terraform

violation[{"id":"AWS_VPN_EnforceClientRoute","impact":"Clients may route network traffic without enforcement, leading to unauthorized access","resolution":"Enable client_route_enforcement_options.enforce_client_route","severity":"MEDIUM"}] {
  input.kind == "terraform"
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  not after.client_route_enforcement_options.enforce_client_route
}