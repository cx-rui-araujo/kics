package main

__kics_meta__ := {
  "id": "AWS1001",
  "title": "Ensure Client VPN endpoint enforces routes",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "category": "Network Security"
}

violation[{
  msg: msg
}] {
  rc := input.ResourceChanges[_]
  rc.Type == "aws_ec2_client_vpn_endpoint"
  after := rc.Change.After
  not after.client_route_enforcement_options
  msg := sprintf("Client VPN endpoint %s has no client_route_enforcement_options set, potentially allowing unauthorized access", [rc.Address])
}

violation[{
  msg: msg
}] {
  rc := input.ResourceChanges[_]
  rc.Type == "aws_ec2_client_vpn_endpoint"
  after := rc.Change.After
  options := after.client_route_enforcement_options[0]
  options.enforce_all_routes == false
  msg := sprintf("Client VPN endpoint %s has client_route_enforcement_options.enforce_all_routes set to false, potentially allowing unauthorized access", [rc.Address])
}