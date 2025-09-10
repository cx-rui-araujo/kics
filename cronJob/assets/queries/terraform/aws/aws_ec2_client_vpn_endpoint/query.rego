package main

violation[{
  "msg": msg,
  "metadata": {"resource": resource.Address}
}] {
  resource := input.resource
  resource.Type == "aws_ec2_client_vpn_endpoint"
  # Check that client_route_enforcement_options block exists and enforcement is enabled
  not resource.Primary.Attributes["client_route_enforcement_options.enable_client_route_enforcement"] == "true"
  msg := "Client VPN endpoint route enforcement is not enabled or misconfigured, allowing unrestricted client access to VPC resources."
}