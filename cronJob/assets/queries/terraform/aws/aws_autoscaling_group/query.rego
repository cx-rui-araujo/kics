package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	auto := input.document[i].resource.aws_autoscaling_group[name]
	not common_lib.valid_key(auto, "tags")
	not common_lib.valid_key(auto, "tag")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_autoscaling_group",
		"resourceName": tf_lib.get_resource_name(auto, name),
		"searchKey": sprintf("aws_autoscaling_group[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'tags' or 'tag' should be defined and not null",
		"keyActualValue": "'tags' and 'tag' are undefined or null",
		"searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name], []),
	}
}

# New rule to ensure capacity_reservation_target is defined when capacity_reservation_specification is used
CxPolicy[result] {
	auto := input.document[i].resource.aws_autoscaling_group[name]
	common_lib.valid_key(auto, "capacity_reservation_specification")
	spec := auto.capacity_reservation_specification[0]
	not common_lib.valid_key(spec, "capacity_reservation_target")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_autoscaling_group",
		"resourceName": tf_lib.get_resource_name(auto, name),
		"searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'capacity_reservation_target' should be defined",
		"keyActualValue": "'capacity_reservation_target' is undefined",
		"searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name, "capacity_reservation_specification"], []),
	}
}