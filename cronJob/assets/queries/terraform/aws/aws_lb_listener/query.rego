package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib
import data.json

lb := {"aws_alb_listener", "aws_lb_listener"}

# Existing rules omitted for brevity...

# New rule: Missing http2 attribute (defaults to true => HTTP/2 enabled)
CxPolicy[result] {
    resource := input.document[i].resource[lb[idx]][name]
    check_application(resource)
    not common_lib.valid_key(resource, "http2")

    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s]", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'http2' should be set to 'false' to disable HTTP2",
        "keyActualValue": "'http2' is missing",
        "remediation": "http2 = false",
        "remediationType": "addition",
    }
}

# New rule: http2 explicitly enabled
CxPolicy[result] {
    resource := input.document[i].resource[lb[idx]][name]
    check_application(resource)
    resource.http2 == true

    result := {
        "documentId": input.document[i].id,
        "resourceType": lb[idx],
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("%s[%s].http2", [lb[idx], name]),
        "searchLine": common_lib.build_search_line(["resource", lb[idx], name, "http2"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'http2' should be 'false' to disable HTTP2",
        "keyActualValue": sprintf("'http2' is set to '%v'", [resource.http2]),
        "remediation": json.marshal({"before": sprintf("%v", [resource.http2]), "after": false}),
        "remediationType": "replacement",
    }
}