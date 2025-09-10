package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
  document = input.document[i]
  resource = document.resource.aws_autoscaling_group[name]
  # Check capacity_reservation_specification block exists
  common_lib.valid_key(resource, "capacity_reservation_specification")
  spec := resource.capacity_reservation_specification[0]
  # If preference is 'open', then a specific target must be provided
  spec.capacity_reservation_preference == "open"
  not common_lib.valid_key(spec, "capacity_reservation_target")

  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_autoscaling_group",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
    "issueType": "MissingAttribute",
    "keyExpectedValue": "'capacity_reservation_target' should be defined when 'capacity_reservation_preference' is 'open'",
    "keyActualValue": "'capacity_reservation_target' is undefined",
    "searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification"], []),
  }
}