package terraform.AWS.ec2

__rego_meta__ := {
  "id": "AWS_EC2_CLIENT_VPN_ENDPOINT_1",
  "title": "Ensure client_route_enforcement_options is enabled on AWS EC2 Client VPN Endpoint",
  "severity": "HIGH",
  "type": "security",
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.change.after.resource_type == "aws_ec2_client_vpn_endpoint"
  opts := resource.change.after.values.client_route_enforcement_options
  opts.enabled == false
}