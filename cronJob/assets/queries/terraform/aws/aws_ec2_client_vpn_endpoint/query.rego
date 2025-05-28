package main

__rego_metadata__ = {"id":"AWS0001","title":"Ensure AWS EC2 Client VPN endpoint enforces client routes","severity":"MEDIUM"}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  # client_route_enforcement_options must be set and enforce routes
  not after.client_route_enforcement_options
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  # enforcement disabled if document_enforcement is NONE
  after.client_route_enforcement_options.document_enforcement == "NONE"
}