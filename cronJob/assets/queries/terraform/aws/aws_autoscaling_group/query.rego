package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

// Enhanced policy: ensure ASG capacity_reservation_specification includes a valid group identifier
CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]

    # If capacity_reservation_specification is set but missing group identifier
    common_lib.valid_key(resource, "capacity_reservation_specification")
    cap := resource.capacity_reservation_specification[0]
    not common_lib.valid_key(cap, "capacity_reservation_group_identifier")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "capacity_reservation_specification[0].capacity_reservation_group_identifier should be defined and not empty",
        "keyActualValue": "capacity_reservation_group_identifier is undefined or empty",
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification"], []),
    }
}