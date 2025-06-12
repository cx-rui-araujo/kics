package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]

    common_lib.valid_key(resource, "capacity_reservation_specification")
    resource.capacity_reservation_specification[0].capacity_reservation_preference == "none"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification[0].capacity_reservation_preference should not be 'none'", [name]),
        "keyActualValue": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification[0].capacity_reservation_preference is 'none'", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification"], []),
    }
}
