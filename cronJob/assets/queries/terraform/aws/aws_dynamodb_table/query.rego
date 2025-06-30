package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# New rule to ensure recovery_period_in_days is not too low
CxPolicy[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	# Ensure point_in_time_recovery block exists
	common_lib.valid_key(resource, "point_in_time_recovery")
	# Check the recovery_period_in_days value
	period := resource.point_in_time_recovery.recovery_period_in_days
	period < 35

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dynamodb_table",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.recovery_period_in_days", [name]),
		"searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","recovery_period_in_days"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be at least 35",
		"keyActualValue": sprintf("aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is set to %v", [period]),
		"remediation": json.marshal({"before": period, "after": 35}),
		"remediationType": "replacement",
	}
}