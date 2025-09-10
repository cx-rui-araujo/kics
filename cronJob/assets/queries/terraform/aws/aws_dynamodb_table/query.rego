package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Detects if recovery_period_in_days is set below the recommended minimum of 7 days
CxPolicy[result] {
    resource := input.document[i].resource.aws_dynamodb_table[name]
    # Ensure the point_in_time_recovery block is enabled
    resource.point_in_time_recovery.enabled == true
    # Check if recovery_period_in_days is set and less than 7
    resource.point_in_time_recovery.recovery_period_in_days < 7

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
        "keyExpectedValue": "recovery_period_in_days should be at least 7",
        "keyActualValue": sprintf("recovery_period_in_days is %v", [resource.point_in_time_recovery.recovery_period_in_days]),
        "remediation": json.marshal({
            "before": tostring(resource.point_in_time_recovery.recovery_period_in_days),
            "after": "7"
        }),
        "remediationType": "replacement",
    }
}