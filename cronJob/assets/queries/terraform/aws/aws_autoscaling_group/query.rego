package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
	auto := input.document[i].resource.aws_autoscaling_group[name]
	not common_lib.valid_key(auto, "tags")
	not common_lib.valid_key(auto, "tag")
	not common_lib.valid_key(auto, "capacity_reservation_specification")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_autoscaling_group",
		"resourceName": tf_lib.get_resource_name(auto, name),
		"searchKey": sprintf("aws_autoscaling_group[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'tags', 'tag' or 'capacity_reservation_specification' should be defined and not null",
		"keyActualValue": "'tags', 'tag' and 'capacity_reservation_specification' are undefined or null",
		"searchLine": common_lib.build_search_line(["resource", "aws_autoscaling_group", name], []),
	}
}

CxPolicy[result] {
	module := input.document[i].module[name]

	keyToCheck := common_lib.get_module_equivalent_key("aws", module.source, "aws_autoscaling_group", "tags")
	not common_lib.valid_key(module, keyToCheck)
	tagsAsMap := common_lib.get_module_equivalent_key("aws", module.source, "aws_autoscaling_group", "tags_as_map")
	not common_lib.valid_key(module, tagsAsMap)
	crs := common_lib.get_module_equivalent_key("aws", module.source, "aws_autoscaling_group", "capacity_reservation_specification")
	not common_lib.valid_key(module, crs)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "n/a",
		"resourceName": "n/a",
		"searchKey": sprintf("module[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'tags' or 'capacity_reservation_specification' should be defined and not null",
		"keyActualValue": "'tags', 'capacity_reservation_specification' are undefined or null",
		"searchLine": common_lib.build_search_line(["module", name], []),
	}
}