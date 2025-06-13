package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure that when capacity reservation preference is 'open', a resource group ARN is supplied
CxPolicy[result] {
	document = input.document[i]
	resource = document.resource.aws_autoscaling_group[name]
	# Check that capacity_reservation_specification is provided
	common_lib.valid_key(resource, "capacity_reservation_specification")
	# The preference is set to 'open'
	resource.capacity_reservation_specification.capacity_reservation_preference == "open"
	# Resource group ARN is missing or null
	not common_lib.valid_key(resource.capacity_reservation_specification, "capacity_reservation_resource_group_arn")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_autoscaling_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "'capacity_reservation_resource_group_arn' must be defined when preference is 'open'",
		"keyActualValue": "'capacity_reservation_resource_group_arn' is undefined or null",
		"searchLine": common_lib.build_search_line(["resource","aws_autoscaling_group",name,"capacity_reservation_specification"], []),
	}
}