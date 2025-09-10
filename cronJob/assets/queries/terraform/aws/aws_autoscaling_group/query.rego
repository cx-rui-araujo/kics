package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Original tag checks omitted for brevity...

# New rule to detect missing capacity_reservation_target when using target preference
CxPolicy[result] {
    document := input.document[i]
    resource := document.resource.aws_autoscaling_group[name]
    cr := resource.capacity_reservation_specification
    cr.capacity_reservation_preference == "target"
    not common_lib.valid_key(cr, "capacity_reservation_target")

    result := {
        "documentId": document.id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "capacity_reservation_specification.capacity_reservation_target should be defined when using target preference",
        "keyActualValue": "capacity_reservation_specification.capacity_reservation_target is undefined",
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification"], []),
    }
}