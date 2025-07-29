package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Existing check for PITR disabled
CxPolicy[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	resource.point_in_time_recovery.enabled == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dynamodb_table",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.enabled", [name]),
		"searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","enabled"],[]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.enabled should be set to true",
		"keyActualValue": "aws_dynamodb_table.point_in_time_recovery.enabled is set to false",
		"remediation": json.marshal({"before":"false","after":"true"}),
		"remediationType": "replacement",
	}
}

# New check: recovery_period_in_days missing
CxPolicy[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	resource.point_in_time_recovery.enabled == true
	not common_lib.valid_key(resource.point_in_time_recovery, "recovery_period_in_days")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dynamodb_table",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.recovery_period_in_days", [name]),
		"searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","recovery_period_in_days"],[]),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be set to >=30",
		"keyActualValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is missing",
		"remediation": "point_in_time_recovery {\n  enabled = true\n  recovery_period_in_days = 30\n}",
		"remediationType": "addition",
	}
}

# New check: recovery_period_in_days too low
CxPolicy[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	val := resource.point_in_time_recovery.recovery_period_in_days
	val < 30

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dynamodb_table",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.recovery_period_in_days",[name]),
		"searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","recovery_period_in_days"],[]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be >=30",
		"keyActualValue": sprintf("aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is set to %v",[val]),
		"remediation": json.marshal({"before": tostring(val),"after":"30"}),
		"remediationType": "replacement",
	}
}