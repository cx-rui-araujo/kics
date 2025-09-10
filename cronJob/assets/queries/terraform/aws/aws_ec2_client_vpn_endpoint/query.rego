package main

__rego_metadata__ = { 
  "id": "KICS-999", 
  "title": "Enforce client_route_enforcement_options on AWS EC2 Client VPN Endpoint", 
  "severity": "HIGH", 
  "type": "terraform", 
  "description": "Client VPN endpoints without route enforcement or with enforcement disabled could allow clients to connect to unauthorized networks.", 
  "recommended_actions": "Enable client_route_enforcement_options by setting enabled = true." 
}

deny[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  not after.client_route_enforcement_options.enabled
}
