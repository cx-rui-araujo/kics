package terraform.aws.ec2

__rego_metadata__ = {
  "id": "AWS999",
  "title": "Ensure client_route_enforcement_options is enabled in aws_ec2_client_vpn_endpoint",
  "severity": "MEDIUM",
  "type": "terraform",
  "category": "Misconfiguration"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  not resource.change.after.client_route_enforcement_options
  msg = "Missing client_route_enforcement_options block on aws_ec2_client_vpn_endpoint"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  options := resource.change.after.client_route_enforcement_options[0]
  options.enabled == false
  msg = "client_route_enforcement_options is not enabled, route enforcement is disabled"
}