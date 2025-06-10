package main

__rego_metadata__ = {
    "id": "AWSClientVPNRouteEnforcementDisabled",
    "title": "Ensure AWS EC2 Client VPN endpoint enables client route enforcement",
    "severity": "MEDIUM",
    "type": "violation",
}

violation[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_ec2_client_vpn_endpoint"
    after := resource.change.after
    # If client_route_enforcement_options is missing or enforce_routes is not true, it's a misconfiguration
    not (after.client_route_enforcement_options != null && after.client_route_enforcement_options.enforce_routes == true)
}