package terraform

__rego_metadata__ := {"id": "KICS-42424-1", "title": "Ensure AWS EC2 Client VPN Endpoint enforces client routes", "severity": "HIGH", "type": "Terraform Security Check"}

deny[msg] {
  resource := input.Resource[_]
  resource.Type == "aws_ec2_client_vpn_endpoint"
  not resource.Values.client_route_enforcement_options
  msg := sprintf("Resource '%s' does not define client_route_enforcement_options, disabling route enforcement", [resource.Name])
}

deny[msg] {
  resource := input.Resource[_]
  resource.Type == "aws_ec2_client_vpn_endpoint"
  options := resource.Values.client_route_enforcement_options[0]
  options.policy == "NO_ENFORCEMENT"
  msg := sprintf("Resource '%s' has client_route_enforcement_options.policy set to NO_ENFORCEMENT, allowing unfiltered traffic", [resource.Name])
}