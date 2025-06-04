package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Detect aws_autoscaling_group with an incorrect capacity_reservation_preference
CxPolicy[result] {
    document := input.document[i]
    resource := document.resource.aws_autoscaling_group[name]
    # Check if capacity_reservation_specification is defined
    common_lib.valid_key(resource, "capacity_reservation_specification")
    spec := resource.capacity_reservation_specification[0]
    # Vulnerable if preference is 'open' instead of 'targeted'
    spec.capacity_reservation_preference == "open"

    result := {
        "documentId": document.id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification[0].capacity_reservation_preference", [name]),
        "issueType": "Misconfiguration",
        "keyExpectedValue": "capacity_reservation_preference should be 'targeted'",
        "keyActualValue": sprintf("capacity_reservation_preference is '%s'", [spec.capacity_reservation_preference]),
        "searchLine": common_lib.build_search_line(["resource","aws_autoscaling_group",name,"capacity_reservation_specification"], []),
    }
}