package main

violation[{"msg": msg, "resource": resource.address}] {
    input.kind == "terraform"
    resource := input.resource_changes[_]
    resource.type == "aws_ec2_client_vpn_endpoint"
    after := resource.change.after
    not after.client_route_enforcement_options
    msg := "Missing client_route_enforcement_options block to enforce client routes"
}

violation[{"msg": msg, "resource": resource.address}] {
    input.kind == "terraform"
    resource := input.resource_changes[_]
    resource.type == "aws_ec2_client_vpn_endpoint"
    after := resource.change.after
    opts := after.client_route_enforcement_options
    opts.enforce_client_routes != true
    msg := "client_route_enforcement_options.enforce_client_routes should be true"
}