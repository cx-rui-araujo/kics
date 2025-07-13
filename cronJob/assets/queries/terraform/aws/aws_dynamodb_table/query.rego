package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Detect if recovery_period_in_days is set below the recommended 35 days
CxPolicy[result] {
	resource := input.document[i].resource[name]
	name == "aws_dynamodb_table"
	res := resource[m]

	# Ensure PITR is enabled but recovery period is too low
	res.point_in_time_recovery.enabled == true
	res.point_in_time_recovery.recovery_period_in_days < 35

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dynamodb_table",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dynamodb_table[{{%s}}].point_in_time_recovery.recovery_period_in_days", [m]),
		"searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","recovery_period_in_days"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be >= 35",
		"keyActualValue": sprintf("aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is set to %d", [res.point_in_time_recovery.recovery_period_in_days]),
		"remediation": json.marshal({"before": sprintf("%d", [res.point_in_time_recovery.recovery_period_in_days]), "after": "35"}),
		"remediationType": "replacement",
	}
}