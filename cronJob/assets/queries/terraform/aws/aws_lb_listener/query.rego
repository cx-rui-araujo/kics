package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Define allowed strong TLS policies
allowed_policies := {"ELBSecurityPolicy-TLS-1-2-2017-01", "ELBSecurityPolicy-FS-1-2-Res-2020-10"}

# Helper to detect bad or missing ssl_policy
bad_or_missing_ssl_policy(resource) {
    not common_lib.valid_key(resource, "ssl_policy")
} else = true {
    common_lib.valid_key(resource, "ssl_policy")
    not resource.ssl_policy in allowed_policies
}

# Cx policy to catch missing or insecure SSL policy on HTTPS listeners
CxPolicy[result] {
    # Target AWS ALB/LB listeners
    lb := ["aws_alb_listener", "aws_lb_listener"]
    resource := input.document[i].resource[lb[idx]][name]

    # Only HTTPS listeners
    resource.protocol == "HTTPS"

    # Missing or insecure ssl_policy detected
    bad_or_missing_ssl_policy(resource)

    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].ssl_policy", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "ssl_policy"], []),
        "issueType": "MissingOrInsecureValue",
        "keyExpectedValue": sprintf("'ssl_policy' should be one of %v", [allowed_policies]),
        "keyActualValue": sprintf("'%v'", [resource.ssl_policy]),
        "remediation": "ssl_policy = \"ELBSecurityPolicy-TLS-1-2-2017-01\"",
        "remediationType": "addition"
    }
}