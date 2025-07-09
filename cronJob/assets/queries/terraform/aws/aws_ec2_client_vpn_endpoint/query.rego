package main

violation[issue] {
  resource := input.Resources[_]
  resource.Type == "aws_ec2_client_vpn_endpoint"
  not resource.Values.client_route_enforcement_options
  issue := {
    "ResourceName": resource.Name,
    "Message": "Client VPN Endpoint has client_route_enforcement_options disabled or not configured, potentially allowing unauthorized network access."
  }
}

violation[issue] {
  resource := input.Resources[_]
  resource.Type == "aws_ec2_client_vpn_endpoint"
  resource.Values.client_route_enforcement_options.enabled == false
  issue := {
    "ResourceName": resource.Name,
    "Message": "Client VPN Endpoint has client_route_enforcement_options disabled or not configured, potentially allowing unauthorized network access."
  }
}