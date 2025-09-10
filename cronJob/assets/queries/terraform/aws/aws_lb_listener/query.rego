package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

lb := {"aws_alb_listener", "aws_lb_listener"}

// Existing rule: ALB Listening on HTTP - Missing redirect default_action
CxPolicy[result] {
    resource := input.document[i].resource[lb[idx]][name]

    check_application(resource)
    is_http(resource)

    not common_lib.valid_key(resource.default_action, "redirect")

    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].default_action", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "default_action"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'default_action.redirect.protocol' should be equal to 'HTTPS'",
        "keyActualValue": "'default_action.redirect' is missing",
    }
}

// Existing rule: ALB Listening on HTTP - Missing redirect.protocol
CxPolicy[result] {
    resource := input.document[i].resource[lb[idx]][name]

    check_application(resource)
    is_http(resource)

    not common_lib.valid_key(resource.default_action.redirect, "protocol")

    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].default_action.redirect", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "default_action", "redirect"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'default_action.redirect.protocol' should be equal to 'HTTPS'",
        "keyActualValue": "'default_action.redirect.protocol' is missing",
        "remediation": "protocol = \"HTTPS\"",
        "remediationType": "addition",
    }
}

// Existing rule: ALB Listening on HTTP - Incorrect redirect.protocol
CxPolicy[result] {
    resource := input.document[i].resource[lb[idx]][name]

    check_application(resource)
    is_http(resource)

    upper(resource.default_action.redirect.protocol) != "HTTPS"

    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].default_action.redirect.protocol", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "default_action", "redirect", "protocol"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'default_action.redirect.protocol' should be equal to 'HTTPS'",
        "keyActualValue": sprintf("'default_action.redirect.protocol' is equal '%s'", [resource.default_action.redirect.protocol]),
        "remediation": json.marshal({
            "before": sprintf("%s", [resource.default_action.redirect.protocol]),
            "after": "HTTPS"
        }),
        "remediationType": "replacement",
    }
}

// New rule: Enforce ssl_policy on secure listeners to avoid default weak TLS policies
CxPolicy[result] {
    resource := input.document[i].resource[lb[idx]][name]

    check_application(resource)
    is_secure(resource)

    not common_lib.valid_key(resource, "ssl_policy")

    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].ssl_policy", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "ssl_policy"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'ssl_policy' should be defined for HTTPS/TLS listeners to enforce strong ciphers",
        "keyActualValue": "'ssl_policy' is missing",
        "remediation": "ssl_policy = \"ELBSecurityPolicy-2016-08\"",
        "remediationType": "addition",
    }
}

// Helpers
is_http(resource) {
    upper(resource.protocol) == "HTTP"
}

is_http(resource) {
    not common_lib.valid_key(resource, "protocol")
}

is_secure(resource) {
    upper(resource.protocol) == "HTTPS" or upper(resource.protocol) == "TLS"
}

is_application(resource) {
    resource.load_balancer_type == "application"
}

is_application(resource) {
    not common_lib.valid_key(resource, "load_balancer_type")
}

check_application(resource) {
    lbs := {"aws_alb", "aws_lb"}
    lb_info := split(resource.load_balancer_arn, ".")
    lb_name = lb_info[1]
    lb := input.document[_].resource[lbs[idx]][name]
    lb_name == name
    is_application(lb)
}