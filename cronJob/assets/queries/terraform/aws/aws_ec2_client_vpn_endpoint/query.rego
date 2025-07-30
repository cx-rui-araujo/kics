package terraform.analysis

__rego_metadata__ := {
  "id": "AWS057",
  "title": "Client VPN endpoint should have client route enforcement enabled",
  "severity": "HIGH",
  "type": "VIOLATION",
  "documentation": {
    "issue": "Disabling client route enforcement on a Client VPN endpoint can allow clients to access unauthorized network routes.",
    "recommendation": "Set client_route_enforcement_options.enabled to true to restrict client access to only allowed routes."
  }
}

violation[{
  "msg": msg,
  "resource": resource_name
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ec2_client_vpn_endpoint"
  after := resource.change.after
  opts := after.client_route_enforcement_options[_]
  opts.enabled == false
  resource_name := resource.address
  msg := sprintf("Resource '%s' has client_route_enforcement_options.enabled set to false, which may allow unauthorized network access", [resource_name])
}