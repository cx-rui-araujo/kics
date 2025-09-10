package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Existing policies omitted for brevity

# New policy to validate recovery_period_in_days range
CxPolicy[result] {
    resource := input.document[i].resource.aws_dynamodb_table[name]
    pt := resource.point_in_time_recovery
    # Ensure recovery_period_in_days is defined and within AWS valid range (1-35 days)
    recovery_days := pt.recovery_period_in_days
    (recovery_days < 1 || recovery_days > 35)

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
        "keyExpectedValue": "recovery_period_in_days should be between 1 and 35",
        "keyActualValue": sprintf("recovery_period_in_days is set to %v", [recovery_days]),
        "remediation": json.marshal({
            "before": sprintf("%v", [recovery_days]),
            "after": "35"
        }),
        "remediationType": "replacement",
    }
}