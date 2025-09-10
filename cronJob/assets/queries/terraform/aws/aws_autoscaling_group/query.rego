package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure capacity_reservation_specification is defined on ASG to avoid unexpected instance evictions
CxPolicy[result] {
    auto := input.document[i].resource.aws_autoscaling_group[name]
    not common_lib.valid_key(auto, "capacity_reservation_specification")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(auto, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'capacity_reservation_specification' should be defined and not null",
        "keyActualValue": "'capacity_reservation_specification' is undefined or null",
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name], []),
    }
}