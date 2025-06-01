package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

lb := {"aws_alb_listener", "aws_lb_listener"}

# Existing policies omitted for brevity...

# New rule: Ensure HTTPS listeners define a secure ssl_policy
CxPolicy[result] {
    resource := input.document[i].resource[lb[idx]][name]
    check_application(resource)
    upper(resource.protocol) == "HTTPS"
    not common_lib.valid_key(resource, "ssl_policy")

    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].ssl_policy", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "ssl_policy"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'ssl_policy' should be defined for HTTPS listeners",
        "keyActualValue": "'ssl_policy' is missing",
        "remediation": "ssl_policy = \"ELBSecurityPolicy-TLS-1-2-2017-01\"",
        "remediationType": "addition",
    }
}