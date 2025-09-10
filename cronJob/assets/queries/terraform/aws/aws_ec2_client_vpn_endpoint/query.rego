package main

violation[message] {
  resource := input.terraform.resources[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  not resource.values.client_route_enforcement_options
  message := sprintf("Resource '%s' is missing client_route_enforcement_options, allowing clients to bypass enforced routes.", [resource.address])
}