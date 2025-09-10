package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Updated policy to ensure capacity_reservation_specification is defined on ASG
CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]

    # Detect missing capacity_reservation_specification block
    not common_lib.valid_key(resource, "capacity_reservation_specification")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'capacity_reservation_specification' should be defined and not null",
        "keyActualValue": "'capacity_reservation_specification' is undefined or null",
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name], []),
    }
}