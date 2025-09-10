package terraform.aws.vpn

__rego_metadata__ := {"id": "AWS_CVPN_001", "title": "Client VPN endpoint has client route enforcement disabled", "severity": "HIGH", "type": "MISCONFIGURATION"}

deny[{{"resource": resource.address, "message": message}}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  attrs := resource.change.after.client_route_enforcement_options
  attrs.enforced == false
  message := sprintf("Client VPN endpoint '%s' has client_route_enforcement_options.enforced set to false; unauthorized networks may be accessed.", [resource.address])
}