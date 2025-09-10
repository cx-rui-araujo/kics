package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure PITR recovery period is at least 7 days
CxPolicy[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	rec := resource.point_in_time_recovery
	rec.enabled == true
	rec.recovery_period_in_days < 7

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dynamodb_table",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.recovery_period_in_days", [name]),
		"searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","recovery_period_in_days"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be >= 7",
		"keyActualValue": sprintf("aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is set to %v", [rec.recovery_period_in_days]),
		"remediation": json.marshal({"before": sprintf("%v", [rec.recovery_period_in_days]), "after": "7"}),
		"remediationType": "replacement",
	}
}

# Flag if recovery_period_in_days is missing entirely
CxPolicy[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	rec := resource.point_in_time_recovery
	rec.enabled == true
	not common_lib.valid_key(rec, "recovery_period_in_days")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dynamodb_table",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.recovery_period_in_days", [name]),
		"searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","recovery_period_in_days"], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be set to >= 7",
		"keyActualValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is missing",
		"remediation": "point_in_time_recovery {\n  enabled = true\n  recovery_period_in_days = 7\n}",
		"remediationType": "addition",
	}
}