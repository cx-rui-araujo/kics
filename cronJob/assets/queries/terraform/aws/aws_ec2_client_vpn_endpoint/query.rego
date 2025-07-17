package terraform.aws.ec2_client_vpn_endpoint

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  opts := after.client_route_enforcement_options
  # If enforcement_enabled is explicitly set to false or not set (defaults to false), it's a misconfiguration
  (opts.enforcement_enabled == false) or not opts.enforcement_enabled
  msg := sprintf("EC2 Client VPN Endpoint '%s' has client_route_enforcement_options.enforcement_enabled set to false or omitted, allowing unrestricted client routes.", [after.tags.Name])
}