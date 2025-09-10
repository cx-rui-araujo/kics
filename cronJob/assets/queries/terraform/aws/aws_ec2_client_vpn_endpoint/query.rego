package terraform.aws.VPN

import data.terraform.resources

__rego_metadata__ := {
  "id": "AWS_CLIENT_VPN_ROUTE_ENFORCEMENT",
  "title": "Ensure 'enforce_client_routes' is enabled for AWS EC2 Client VPN Endpoint",
  "severity": "MEDIUM",
  "type": "BEST_PRACTICE"
}

violation[resource] {
  resource := data.terraform.resources.aws_ec2_client_vpn_endpoint[_]
  not (resource.values.client_route_enforcement_options.enforce_client_routes)
}