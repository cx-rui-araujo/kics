package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Updated policy to ensure capacity_reservation_specification.preference is set to 'open' to guarantee reserved capacity availability
CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]

    # Check existing ELB/target group misconfiguration
    count(resource.load_balancers) == 0
    not has_target_group_arns(resource, "target_group_arns")
    # New check for capacity reservation preference
    not valid_capacity_reservation(resource)

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification.capacity_reservation_preference", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "capacity_reservation_specification.capacity_reservation_preference should be set to 'open'",
        "keyActualValue": sprintf("capacity_reservation_preference is '%v'", [resource.capacity_reservation_specification.capacity_reservation_preference]),
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification", "capacity_reservation_preference"], []),
    }
}

# Helper to validate capacity reservation preference
valid_capacity_reservation(resource) {
    resource.capacity_reservation_specification.capacity_reservation_preference == "open"
}

# Existing helper for target groups
has_target_group_arns(resource, key) {
    not is_array(resource[key])
    resource[key] != ""
} else {
    is_array(resource[key])
    count(resource[key]) > 0
}