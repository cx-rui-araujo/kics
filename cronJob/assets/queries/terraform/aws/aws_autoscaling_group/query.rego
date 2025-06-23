package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]

    common_lib.valid_key(resource, "capacity_reservation_specification")
    resource.capacity_reservation_specification.capacity_reservation_preference == "open"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification.capacity_reservation_preference", [name]),
        "issueType": "InsecureConfiguration",
        "keyExpectedValue": "capacity_reservation_preference should not be 'open'",
        "keyActualValue": sprintf("capacity_reservation_preference is '%s'", [resource.capacity_reservation_specification.capacity_reservation_preference]),
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification", "capacity_reservation_preference"], []),
    }
}