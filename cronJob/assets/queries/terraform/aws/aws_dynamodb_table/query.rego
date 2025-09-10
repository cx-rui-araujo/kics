package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# New rule to ensure point_in_time_recovery.recovery_period_in_days is set and sufficient
CxPolicy[result] {
    resource := input.document[i].resource.aws_dynamodb_table[name]
    # PITR must be enabled first
    resource.point_in_time_recovery.enabled == true
    # Check recovery_period_in_days exists and is at least 7
    period := resource.point_in_time_recovery.recovery_period_in_days
    period < 7

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_dynamodb_table",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.recovery_period_in_days", [name]),
        "searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","recovery_period_in_days"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be >= 7",
        "keyActualValue": sprintf("aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is set to %v", [period]),
        "remediation": json.marshal({"before": period, "after": 7}),
        "remediationType": "replacement",
    }
}

# Rule to detect missing recovery_period_in_days attribute
CxPolicy[result] {
    resource := input.document[i].resource.aws_dynamodb_table[name]
    resource.point_in_time_recovery.enabled == true
    not common_lib.valid_key(resource.point_in_time_recovery, "recovery_period_in_days")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_dynamodb_table",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery", [name]),
        "searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be set and >= 7",
        "keyActualValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is missing",
        "remediation": "recovery_period_in_days = 7",
        "remediationType": "addition",
    }
}