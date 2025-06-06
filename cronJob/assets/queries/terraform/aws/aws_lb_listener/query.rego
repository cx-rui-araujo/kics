package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

listeners := {"aws_alb_listener", "aws_lb_listener"}

CxPolicy[result] {
    resource := input.document[i].resource[listeners[idx]][name]
    is_https(resource)
    not common_lib.valid_key(resource, "ssl_policy")
    result := {
        "documentId": input.document[i].id,
        "resourceType": listeners[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].ssl_policy", [listeners[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", listeners[idx], name, "ssl_policy"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'ssl_policy' should be specified for HTTPS listener",
        "keyActualValue": "'ssl_policy' is missing",
        "remediation": "ssl_policy = \"ELBSecurityPolicy-2016-08\"",
        "remediationType": "addition",
    }
}

is_https(resource) {
    upper(resource.protocol) == "HTTPS"
}
