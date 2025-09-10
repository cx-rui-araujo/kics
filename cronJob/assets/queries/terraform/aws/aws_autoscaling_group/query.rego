package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Existing policy: Ensure ELBs or target group ARNs
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

# Existing policy: Ensure tags
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

# New policy: Ensure capacity_reservation_specification is defined
CxPolicy[result] {
	auto := input.document[i].resource.aws_autoscaling_group[name]
	not common_lib.valid_key(auto, "capacity_reservation_specification")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_autoscaling_group",
		"resourceName": tf_lib.get_resource_name(auto, name),
		"searchKey": sprintf("aws_autoscaling_group[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'capacity_reservation_specification' should be defined and not null",
		"keyActualValue": "'capacity_reservation_specification' is undefined or null",
		"searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name], [])
	}
}

has_target_group_arns(resource, key) {
	not is_array(resource[key])
	resource[key] != ""
} else {
	is_array(resource[key])
	count(resource[key]) > 0
}