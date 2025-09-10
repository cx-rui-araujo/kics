package kics

default violation = []

violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  (
    after.client_route_enforcement_options == null
    or after.client_route_enforcement_options[0].enabled == false
  )
  res := {
    "resource": resource.address,
    "message": "Client route enforcement is not enabled, allowing unauthorized network access."
  }
}