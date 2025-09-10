package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Updated policy to enforce both enabled and sufficient retention period
CxPolicy[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	# Ensure point-in-time recovery is enabled
	common_lib.valid_key(resource, "point_in_time_recovery")
	common_lib.valid_key(resource.point_in_time_recovery, "enabled")
	resource.point_in_time_recovery.enabled == true
	# Ensure retention period is at least 7 days
	common_lib.valid_key(resource.point_in_time_recovery, "recovery_period_in_days")
	resource.point_in_time_recovery.recovery_period_in_days >= 7
	# no violation if above holds
}

# Violation when retention period is below threshold
CxPolicy[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	common_lib.valid_key(resource, "point_in_time_recovery")
	common_lib.valid_key(resource.point_in_time_recovery, "recovery_period_in_days")
	resource.point_in_time_recovery.recovery_period_in_days < 7

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dynamodb_table",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dynamodb_table[{%s}].point_in_time_recovery.recovery_period_in_days", [name]),
		"searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","recovery_period_in_days"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be >= 7",
		"keyActualValue": sprintf("aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is set to %v", [resource.point_in_time_recovery.recovery_period_in_days]),
		"remediation": json.marshal({"before": sprintf("%v", [resource.point_in_time_recovery.recovery_period_in_days]), "after": "7"}),
		"remediationType": "replacement",
	}
}