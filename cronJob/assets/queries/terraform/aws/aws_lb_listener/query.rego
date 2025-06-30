package Cx
import data.generic.common as common_lib
import data.generic.terraform as tf_lib

lb := {"aws_alb_listener","aws_lb_listener"}

CxPolicy[result] {
    resource := input.document[i].resource[lb[idx]][name]
    upper(resource.protocol) == "HTTPS"
    not common_lib.valid_key(resource, "ssl_policy")

    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s]", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'ssl_policy' should be specified for HTTPS listener",
        "keyActualValue": "'ssl_policy' is missing",
        "remediation": "ssl_policy = \"ELBSecurityPolicy-FS-1-2-Res-2020-10\"",
        "remediationType": "addition",
    }
}