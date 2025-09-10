package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Detect open capacity reservations on Auto Scaling Groups
CxPolicy[result] {
    document := input.document[i]
    resource := document.resource.aws_autoscaling_group[name]

    # If the block is missing, AWS defaults to 'open'
    not common_lib.valid_key(resource, "capacity_reservation_specification")

    result := {
        "documentId": document.id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "capacity_reservation_specification.capacity_reservation_preference should be set to 'targeted'",
        "keyActualValue": "capacity_reservation_specification is undefined (defaults to 'open')",
        "searchLine": common_lib.build_search_line(["resource","aws_autoscaling_group",name], []),
    }
}

CxPolicy[result] {
    document := input.document[i]
    resource := document.resource.aws_autoscaling_group[name]
    spec := resource.capacity_reservation_specification[0]

    # Explicitly set to open
    spec.capacity_reservation_preference == "open"

    result := {
        "documentId": document.id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "capacity_reservation_preference should be 'targeted'",
        "keyActualValue": sprintf("capacity_reservation_preference is '%s'", [spec.capacity_reservation_preference]),
        "searchLine": common_lib.build_search_line(["resource","aws_autoscaling_group",name,"capacity_reservation_specification"], []),
    }
}