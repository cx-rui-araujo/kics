package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Existing rule: ensure load_balancers defined or target_group_arns
CxPolicy[result] {
	document = input.document[i]
	resource = document.resource.aws_autoscaling_group[name]

	count(resource.load_balancers) == 0
	not has_target_group_arns(resource, "target_group_arns")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_autoscaling_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_autoscaling_group[%s].load_balancers", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": sprintf("aws_autoscaling_group[%s].load_balancers should be set and not empty", [name]),
		"keyActualValue": sprintf("aws_autoscaling_group[%s].load_balancers is empty", [name]),
		"searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "load_balancers"], []),
	}
}

# New rule: ensure capacity_reservation_specification target ID when using 'targeted' preference
CxPolicy[result] {
	document = input.document[i]
	resource = document.resource.aws_autoscaling_group[name]

	# capacity_reservation_specification block must exist
	common_lib.valid_key(resource, "capacity_reservation_specification")
	reservation := resource.capacity_reservation_specification[0]

	# If preference is 'targeted', a reservation ID must be provided
	reservation.capacity_reservation_preference == "targeted"
	not common_lib.valid_key(reservation.capacity_reservation_target, "capacity_reservation_id")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_autoscaling_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification[0].capacity_reservation_target.capacity_reservation_id", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification[0].capacity_reservation_target.capacity_reservation_id should be set when preference is 'targeted'", [name]),
		"keyActualValue": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification[0].capacity_reservation_target.capacity_reservation_id is undefined", [name]),
		"searchLine": common_lib.build_search_line(["resource","aws_autoscaling_group",name,"capacity_reservation_specification"], []),
	}
}

has_target_group_arns(resource, key) {
	not is_array(resource[key])
	resource[key] != ""
} else {
	is_array(resource[key])
	count(resource[key]) > 0
}