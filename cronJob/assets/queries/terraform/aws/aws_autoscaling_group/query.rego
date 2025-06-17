package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    document := input.document[i]
    resource := document.resource.aws_autoscaling_group[name]

    # Ensure capacity_reservation_specification is defined to avoid launch failures
    not common_lib.valid_key(resource, "capacity_reservation_specification")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'capacity_reservation_specification' should be defined",
        "keyActualValue": "'capacity_reservation_specification' is undefined",
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name], []),
    }
}