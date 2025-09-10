package terraform.aws_ec2_client_vpn_endpoint

# Ensure client route enforcement options are enabled to prevent unauthorized subnet access

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  # Detect if enforcement is explicitly disabled
  options := resource.change.after.client_route_enforcement_options
  options[0].enforce_source_subnet == false
  msg := sprintf("EC2 Client VPN endpoint '%s' has enforce_source_subnet disabled in client_route_enforcement_options, which may allow unauthorized network access", [resource.address])
}