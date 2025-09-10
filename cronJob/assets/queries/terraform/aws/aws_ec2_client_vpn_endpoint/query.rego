package terraform.analysis

deny[rule] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  opts := after.client_route_enforcement_options
  opts.enforcement_enabled == false
  rule := {
    "msg": "Client VPN endpoint has route enforcement disabled, allowing clients to access unapproved routes.",
    "severity": "HIGH",
    "resource": resource.address
  }
}