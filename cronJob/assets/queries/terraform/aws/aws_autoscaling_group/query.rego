package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure capacity_reservation_specification is defined
CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]

    not common_lib.valid_key(resource, "capacity_reservation_specification")

    result := {
        "documentId": document.id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'capacity_reservation_specification' should be defined and use 'capacity_reservation_preference = \"open\"'",
        "keyActualValue": "'capacity_reservation_specification' is undefined",
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name], [])
    }
}

# Ensure capacity_reservation_preference is set to 'open'
CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]

    common_lib.valid_key(resource, "capacity_reservation_specification")
    pref := resource.capacity_reservation_specification.capacity_reservation_preference
    pref != "open"

    result := {
        "documentId": document.id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification.capacity_reservation_preference", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "'capacity_reservation_preference' should be set to 'open'",
        "keyActualValue": sprintf("capacity_reservation_preference is '%s'", [pref]),
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification", "capacity_reservation_preference"], [])
    }
}