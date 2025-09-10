package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Check if Point-In-Time Recovery is disabled
CxPolicy[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	resource.point_in_time_recovery.enabled == false

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dynamodb_table",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.enabled", [name]),
		"searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","enabled"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.enabled should be set to true",
		"keyActualValue": "aws_dynamodb_table.point_in_time_recovery.enabled is set to false",
		"remediation": json.marshal({"before": "false","after": "true"}),
		"remediationType": "replacement"
	}
}

# Check if Point-In-Time Recovery block is missing
CxPolicy[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	not common_lib.valid_key(resource, "point_in_time_recovery")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dynamodb_table",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dynamodb_table[%s]", [name]),
		"searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name], []),
		"issueType": "MissingAttribute",
		"keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.enabled should be enabled",
		"keyActualValue": "aws_dynamodb_table.point_in_time_recovery is missing",
		"remediation": "point_in_time_recovery {\n\t enabled = true \n}",
		"remediationType": "addition"
	}
}

# NEW: Check for insufficient recovery period
CxPolicy[result] {
	resource := input.document[i].resource.aws_dynamodb_table[name]
	resource.point_in_time_recovery.enabled == true
	resource.point_in_time_recovery.recovery_period_in_days < 7

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_dynamodb_table",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.recovery_period_in_days", [name]),
		"searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","recovery_period_in_days"], []),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be >= 7",
		"keyActualValue": sprintf("aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is set to %v", [resource.point_in_time_recovery.recovery_period_in_days]),
		"remediation": json.marshal({"before": sprintf("%v", [resource.point_in_time_recovery.recovery_period_in_days]),"after": "7"}),
		"remediationType": "replacement"
	}
}