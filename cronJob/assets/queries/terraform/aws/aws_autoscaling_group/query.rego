package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure that if capacity_reservation_specification is set, then a valid target ARN is provided
CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]

    # capacity_reservation_specification block must exist
    common_lib.valid_key(resource, "capacity_reservation_specification")
    spec = resource.capacity_reservation_specification

    # capacity_reservation_target block must exist
    not common_lib.valid_key(spec, "capacity_reservation_target")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'capacity_reservation_target.capacity_reservation_resource_group_arn' should be defined and not empty when 'capacity_reservation_specification' is used",
        "keyActualValue": sprintf("capacity_reservation_specification is defined but missing capacity_reservation_target block in aws_autoscaling_group[%s]", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification"], []),
    }
}

CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]
    spec = resource.capacity_reservation_specification
    target = spec.capacity_reservation_target

    # target exists but ARN is empty or missing
    common_lib.valid_key(spec, "capacity_reservation_target")
    (not common_lib.valid_key(target, "capacity_reservation_resource_group_arn"))
    or (target.capacity_reservation_resource_group_arn == "")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification.capacity_reservation_target.capacity_reservation_resource_group_arn", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "capacity_reservation_resource_group_arn should be set and not empty",
        "keyActualValue": sprintf("capacity_reservation_resource_group_arn is empty or undefined in aws_autoscaling_group[%s]", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification", "capacity_reservation_target", "capacity_reservation_resource_group_arn"], []),
    }
}