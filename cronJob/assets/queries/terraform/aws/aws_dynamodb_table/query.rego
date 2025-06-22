package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure DynamoDB point_in_time_recovery.recovery_period_in_days is set to a safe retention period (>=7 days)
CxPolicy[result] {
    resource := input.document[i].resource.aws_dynamodb_table[name]
    # Only evaluate if the attribute is present
    recovery_days := resource.point_in_time_recovery.recovery_period_in_days
    recovery_days < 7

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_dynamodb_table",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.recovery_period_in_days", [name]),
        "searchLine": common_lib.build_search_line([
            "resource", "aws_dynamodb_table", name,
            "point_in_time_recovery", "recovery_period_in_days"
        ], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be >= 7",
        "keyActualValue": sprintf("aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is set to %v", [recovery_days]),
        "remediation": json.marshal({"before": sprintf("%v", [recovery_days]), "after": "7"}),
        "remediationType": "replacement",
    }
}