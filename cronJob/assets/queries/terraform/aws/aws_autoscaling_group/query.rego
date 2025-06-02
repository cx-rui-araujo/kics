package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]
    common_lib.valid_key(resource, "capacity_reservation_specification")
    spec = resource.capacity_reservation_specification[0]
    (not common_lib.valid_key(spec, "capacity_reservation_target") || count(spec.capacity_reservation_target) == 0)
    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification.capacity_reservation_target", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'capacity_reservation_target' should be defined and not empty in 'capacity_reservation_specification' block",
        "keyActualValue": "'capacity_reservation_target' is undefined or empty",
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification", "capacity_reservation_target"], []),
    }
}