package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Existing Auto Scaling Group ELB check and tag policies remain unchanged

# New policy to ensure capacity_reservation_resource_group_arn is set when using resource_group preference
CxPolicy[result] {
    document := input.document[i]
    resource := document.resource.aws_autoscaling_group[name]
    spec := resource.capacity_reservation_specification

    spec.capacity_reservation_preference == "resource_group"
    not common_lib.valid_key(spec, "capacity_reservation_resource_group_arn")

    result := {
        "documentId": document.id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification.capacity_reservation_resource_group_arn", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "capacity_reservation_specification.capacity_reservation_resource_group_arn must be defined when preference is 'resource_group'",
        "keyActualValue": sprintf("capacity_reservation_specification.capacity_reservation_resource_group_arn is undefined for aws_autoscaling_group[%s]", [name]),
        "searchLine": common_lib.build_search_line(["resource","aws_autoscaling_group",name,"capacity_reservation_specification","capacity_reservation_resource_group_arn"], []),
    }
}