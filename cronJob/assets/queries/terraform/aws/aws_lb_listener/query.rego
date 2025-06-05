package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource["aws_lb_listener"][name]

    # Ensure HTTPS listeners explicitly specify ssl_policy
    upper(resource.protocol) == "HTTPS"
    not common_lib.valid_key(resource, "ssl_policy")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_lb_listener",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_lb_listener[%s].ssl_policy", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_lb_listener", name, "ssl_policy"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'ssl_policy' should be specified to a secure policy, not the default",
        "keyActualValue": "'ssl_policy' is missing and defaults to an insecure policy",
        "remediation": "ssl_policy = \"ELBSecurityPolicy-FS-1-2-Res-2020-10\"",
        "remediationType": "addition"
    }
}