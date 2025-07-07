package main

__rego_metadata := {"id":"KICS-001","version":"1.0","title":"Client VPN Endpoint route enforcement disabled","description":"Missing or disabled client_route_enforcement_options can allow clients to bypass route restrictions.","severity":"HIGH","category":"Networking"}

deny[resource] {
  resource := input.resource.aws_ec2_client_vpn_endpoint[_]
  opts := resource.client_route_enforcement_options
  (opts == null) or not opts.require_client_vpn_routes_before_server_connection
}