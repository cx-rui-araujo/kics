package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

// Ensure capacity_reservation_specification is defined to avoid instances launching only on-demand
CxPolicy[result] {
	document := input.document[i]
	resource := document.resource.aws_autoscaling_group[name]

	not common_lib.valid_key(resource, "capacity_reservation_specification")

	result := {
		"documentId": document.id,
		"resourceType": "aws_autoscaling_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_autoscaling_group[%s]", [name]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "capacity_reservation_specification should be defined to ensure instance placement in capacity reservations",
		"keyActualValue": "capacity_reservation_specification is undefined",
		"searchLine": common_lib.build_search_line(["resource","aws_autoscaling_group",name], []),
	}
}