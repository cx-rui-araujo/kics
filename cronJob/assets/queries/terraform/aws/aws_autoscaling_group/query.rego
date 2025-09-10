package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure capacity_reservation_specification.target is defined for AWS Auto Scaling Groups
CxPolicy[result] {
    document = input.document[i]
    resource = document.resource.aws_autoscaling_group[name]

    # capacity_reservation_specification block must exist
    common_lib.valid_key(resource, "capacity_reservation_specification")
    # capacity_reservation_target must be specified inside the block
    not common_lib.valid_key(resource.capacity_reservation_specification, "capacity_reservation_target")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "capacity_reservation_specification.capacity_reservation_target should be defined",
        "keyActualValue": "capacity_reservation_specification.capacity_reservation_target is undefined",
        "searchLine": common_lib.build_search_line([
            "resource", "aws_autoscaling_group", name, "capacity_reservation_specification"
        ], []),
    }
}