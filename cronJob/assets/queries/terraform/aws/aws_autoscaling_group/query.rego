package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Warn when capacity_reservation_specification is declared without a capacity_reservation_target
CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]

    # capacity_reservation_specification block exists
    common_lib.valid_key(resource, "capacity_reservation_specification")

    # capacity_reservation_target must be defined inside the block
    not common_lib.valid_key(resource.capacity_reservation_specification, "capacity_reservation_target")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "capacity_reservation_target should be defined when using capacity_reservation_specification",
        "keyActualValue": "capacity_reservation_target is undefined",
        "searchLine": common_lib.build_search_line(["resource","aws_autoscaling_group", name, "capacity_reservation_specification"], []),
    }
}