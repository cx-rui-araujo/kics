package Cx
import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	document = input.document[i]
	resource = document.resource.aws_autoscaling_group[name]

	# capacity_reservation_specification should be defined to avoid lockout of on-demand fallback
	not common_lib.valid_key(resource, "capacity_reservation_specification")

	result := {
		"documentId": document.id,
		"resourceType": "aws_autoscaling_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_autoscaling_group[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'capacity_reservation_specification' block with 'capacity_reservation_preference' should be defined",
		"keyActualValue": "'capacity_reservation_specification' is undefined",
		"searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name], []),
	}
}

CxPolicy[result] {
	document = input.document[i]
	resource = document.resource.aws_autoscaling_group[name]
	common_lib.valid_key(resource, "capacity_reservation_specification")
	spec = resource.capacity_reservation_specification

	# ensure on-demand fallback is permitted
	spec.capacity_reservation_preference != "open"

	result := {
		"documentId": document.id,
		"resourceType": "aws_autoscaling_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'capacity_reservation_preference' should be set to 'open' to enable on-demand fallback",
		"keyActualValue": sprintf("capacity_reservation_preference is '%s'", [spec.capacity_reservation_preference]),
		"searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification", "capacity_reservation_preference"], []),
	}
}