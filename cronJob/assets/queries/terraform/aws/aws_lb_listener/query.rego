package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

lb := {"aws_alb_listener", "aws_lb_listener"}

# Existing HTTP listener checks omitted for brevity...

# New rule: Ensure HTTPS listeners specify a secure ssl_policy (TLS1.2+)
CxPolicy[result] {
    # Iterate over ALB/NLB listeners
    idx := lb[_]
    resource := input.document[i].resource[lb[idx]][name]

    # Confirm this is an Application Load Balancer listener
    check_application(resource)

    # Only apply to HTTPS listeners
    is_https(resource)

    # ssl_policy must be defined to avoid default insecure policies
    not common_lib.valid_key(resource, "ssl_policy")

    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].ssl_policy", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "ssl_policy"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'ssl_policy' should be defined to enforce TLS1.2+ ciphers",
        "keyActualValue": "'ssl_policy' is missing",
        "remediation": "ssl_policy = \"ELBSecurityPolicy-TLS-1-2-2017-01\"",
        "remediationType": "addition",
    }
}

# Helper to detect HTTPS listeners
is_https(resource) {
    common_lib.valid_key(resource, "protocol")
    upper(resource.protocol) == "HTTPS"
}

# Reuse existing helper to confirm this is an ALB
check_application(resource) {
    lbs := {"aws_alb", "aws_lb"}
    lb_info := split(resource.load_balancer_arn, ".")
    lb_name = lb_info[1]
    lb := input.document[_].resource[lbs[_]][lb_name]
    is_application(lb)
}

is_application(resource) {
    common_lib.valid_key(resource, "load_balancer_type")
    resource.load_balancer_type == "application"
}