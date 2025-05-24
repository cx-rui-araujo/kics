package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    document := input.document[i]
    resource := document.resource.aws_autoscaling_group[name]
    common_lib.valid_key(resource, "capacity_reservation_specification")
    spec := resource.capacity_reservation_specification[0]
    spec.capacity_reservation_preference == "targeted"
    (not common_lib.valid_key(spec, "capacity_reservation_pools") or count(spec.capacity_reservation_pools) == 0)
    result := {
        "documentId": document.id,
        "resourceType": "aws_autoscaling_group",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "'capacity_reservation_pools' must be set and not empty when 'capacity_reservation_preference' is 'targeted'",
        "keyActualValue": sprintf("'capacity_reservation_pools' is undefined or empty while 'capacity_reservation_preference' is 'targeted' for aws_autoscaling_group[%s]", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification"], []),
    }
}
