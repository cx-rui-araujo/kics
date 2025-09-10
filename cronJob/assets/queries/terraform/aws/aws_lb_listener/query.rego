package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

lb := {"aws_alb_listener", "aws_lb_listener"}

# Existing HTTP redirect checks omitted for brevity...

# New rule: detect omitted http2_enabled (default HTTP2 enabled) on HTTPS application listeners
CxPolicy[result] {
    resource := input.document[i].resource[lb[idx]][name]

    # ensure this is an application load balancer listener using HTTPS
    check_application(resource)
    upper(resource.protocol) == "HTTPS"

    # http2_enabled not configured => Terraform omits false, AWS defaults to true
    not common_lib.valid_key(resource, "http2_enabled")

    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].http2_enabled", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "http2_enabled"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'http2_enabled' should be 'false'",
        "keyActualValue": "'http2_enabled' is missing (defaults to true)",
        "remediation": "http2_enabled = false",
        "remediationType": "addition",
    }
}

# New rule: detect explicitly enabled http2_enabled
CxPolicy[result] {
    resource := input.document[i].resource[lb[idx]][name]

    check_application(resource)
    upper(resource.protocol) == "HTTPS"

    common_lib.valid_key(resource, "http2_enabled")
    resource.http2_enabled == true

    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].http2_enabled", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "http2_enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'http2_enabled' should be 'false'",
        "keyActualValue": sprintf("'http2_enabled' is '%v'", [resource.http2_enabled]),
        "remediation": json.marshal({"before": sprintf("%v", [resource.http2_enabled]), "after": false}),
        "remediationType": "replacement",
    }
}