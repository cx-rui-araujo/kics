package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Detects open capacity reservation preference without specifying a targeted reservation, which may cause instances
to launch outside intended reserved capacity
CxPolicy[result] {
	document := input.document[i]
	resource := document.resource.aws_autoscaling_group[name]

	# capacity_reservation_specification is defined as a list with at least one block
	resource.capacity_reservation_specification
	pref := resource.capacity_reservation_specification[0]

	# If preference is 'open', no specific reservation ID is enforced
	pref.capacity_reservation_preference == "open"

	result := {
		"documentId": document.id,
		"resourceType": "aws_autoscaling_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification[0].capacity_reservation_preference", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "capacity_reservation_preference should be 'targeted' with capacity_reservation_target defined",
		"keyActualValue": sprintf("capacity_reservation_preference is '%s'", [pref.capacity_reservation_preference]),
		"searchLine": common_lib.build_search_line(["resource","aws_autoscaling_group",name,"capacity_reservation_specification","capacity_reservation_preference"], []),
	}
}