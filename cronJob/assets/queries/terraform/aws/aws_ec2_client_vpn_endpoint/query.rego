package terraform.aws.ClientVPN

__rego_metadata__ := {"id":"AWS100","title":"Ensure Client VPN uses source routes only enforcement","description":"Client VPN endpoints should enforce that clients can only reach specified routes to reduce risk of unauthorized network access.","severity":"HIGH","provider":"aws","service":"ec2","category":"Network Security"}

violation[resource] {
  resource := tfplan.resource_changes["aws_ec2_client_vpn_endpoint"][_]
  resource.change.after.client_route_enforcement_options
  resource.change.after.client_route_enforcement_options.source_routes_only == false
}