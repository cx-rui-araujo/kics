package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure point in time recovery window is within AWS supported limits (1-35 days)
CxPolicy[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	# PITR must be enabled
	resource.point_in_time_recovery.enabled == true

	# Check recovery_period_in_days exists and is within range
	recovery_days := resource.point_in_time_recovery.recovery_period_in_days
	not (recovery_days >= 1 and recovery_days <= 35)

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dynamodb_table",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.recovery_period_in_days", [name]),
		"searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","recovery_period_in_days"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "point_in_time_recovery.recovery_period_in_days must be between 1 and 35",
		"keyActualValue": sprintf("point_in_time_recovery.recovery_period_in_days is set to %v", [recovery_days]),
		"remediation": json.marshal({"before": recovery_days, "after": 35}),
		"remediationType": "replacement",
	}
}