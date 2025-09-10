package main

import data

violation[issue] {
    resource := data.resource_changes[_]
    resource.type == "aws_cognitoidp_user_pool"
    flows := resource.change.after.user_pool_add_ons.advanced_security_additional_flows
    flows[_] == "ALLOW_CUSTOM_AUTH"
    issue := {
        "resource": resource.address,
        "message": "User pool allows ALLOW_CUSTOM_AUTH flow, which can bypass standard authentication protections"
    }
}