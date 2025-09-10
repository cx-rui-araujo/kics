package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure capacity_reservation_specification allows fallback to on-demand
CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]
    # Only check when capacity_reservation_specification is defined
    common_lib.valid_key(resource, "capacity_reservation_specification")
    spec = resource.capacity_reservation_specification
    # Missing preference or not set to "open"
    (not common_lib.valid_key(spec, "capacity_reservation_preference"))
    or spec.capacity_reservation_preference != "open"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification.capacity_reservation_preference", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "capacity_reservation_preference should be defined and set to 'open' to allow fallback to on-demand instances",
        "keyActualValue": sprintf("capacity_reservation_preference is %v", [spec.capacity_reservation_preference]),
        "searchLine": common_lib.build_search_line([
            "resource", "aws_autoscaling_group", name,
            "capacity_reservation_specification", "capacity_reservation_preference"
        ], []),
    }
}