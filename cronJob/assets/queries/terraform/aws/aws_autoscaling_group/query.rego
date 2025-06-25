package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure capacity_reservation_specification is not set to 'none' which may lead to unpredictable provisioning
CxPolicy[result] {
	document = input.document[i]
	resource = document.resource.aws_autoscaling_group[name]
	spec := resource.capacity_reservation_specification
	spec.capacity_reservation_preference == "none"

	result := {
		"documentId": document.id,
		"resourceType": "aws_autoscaling_group",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_autoscaling_group[%s].capacity_reservation_specification.capacity_reservation_preference", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "capacity_reservation_preference should not be 'none' to guarantee reserved capacity",
		"keyActualValue": sprintf("capacity_reservation_preference is '%s'", [spec.capacity_reservation_preference]),
		"searchLine": common_lib.build_search_line(["resource","aws_autoscaling_group",name,"capacity_reservation_specification","capacity_reservation_preference"], []),
	}
}