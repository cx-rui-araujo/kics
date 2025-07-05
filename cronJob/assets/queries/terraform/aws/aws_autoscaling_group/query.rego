package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	document = input.document[i]
	resource = document.resource.aws_autoscaling_group[name]

	# Ensure that if capacity_reservation_preference is "targeted", a target block must be defined
	common_lib.valid_key(resource, "capacity_reservation_specification")
	pref := resource.capacity_reservation_specification.capacity_reservation_preference
	pref == "targeted"
	not common_lib.valid_key(resource.capacity_reservation_specification, "capacity_reservation_target")

	result := {
		"documentId": document.id,
		"resourceType": "aws_autoscaling_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'capacity_reservation_target' must be specified when 'capacity_reservation_preference' is 'targeted'",
		"keyActualValue": "'capacity_reservation_target' is undefined or empty",
		"searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification"], []),
	}
}