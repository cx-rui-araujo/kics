package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Rule: Ensure capacity_reservation_specification.preference is 'open' to allow fallback to On-Demand
CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]

    # Only check when capacity_reservation_specification is defined
    common_lib.valid_key(resource, "capacity_reservation_specification")
    spec := resource.capacity_reservation_specification

    # If preference is not 'open', ASG may stall when no CR available
    spec.capacity_reservation_preference != "open"

    result := {
        "documentId": document.id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification.capacity_reservation_preference", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "capacity_reservation_specification.capacity_reservation_preference should be 'open'",
        "keyActualValue": sprintf("capacity_reservation_specification.capacity_reservation_preference is '%s'", [spec.capacity_reservation_preference]),
        "searchLine": common_lib.build_search_line(["resource","aws_autoscaling_group", name, "capacity_reservation_specification", "capacity_reservation_preference"], []),
    }
}