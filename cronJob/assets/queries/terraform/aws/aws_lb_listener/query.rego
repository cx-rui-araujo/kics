package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

listener := {"aws_lb_listener"}

CxPolicy[result] {
    resource := input.document[i].resource[listener[idx]][name]
    is_https(resource)
    not common_lib.valid_key(resource, "ssl_policy")
    result := {
        "documentId": input.document[i].id,
        "resourceType": listener[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].ssl_policy", [listener[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", listener[idx], name, "ssl_policy"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'ssl_policy' should be specified to enforce secure protocols",
        "keyActualValue": "'ssl_policy' is missing",
        "remediation": "ssl_policy = \"ELBSecurityPolicy-TLS-1-2-2017-01\"",
        "remediationType": "addition",
    }
}

is_https(resource) {
    upper(resource.protocol) == "HTTPS"
}