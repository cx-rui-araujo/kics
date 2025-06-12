package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource[name]
    name == "aws_dynamodb_table"
    res := resource[m]
    # Ensure PITR is enabled and check recovery window
    res.point_in_time_recovery.enabled == true
    recovery := res.point_in_time_recovery.recovery_period_in_days
    not recovery >= 30

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_dynamodb_table",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.recovery_period_in_days", [m]),
        "searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","recovery_period_in_days"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "point_in_time_recovery.recovery_period_in_days should be >= 30",
        "keyActualValue": sprintf("point_in_time_recovery.recovery_period_in_days is set to %v", [recovery]),
        "remediation": json.marshal({"before": sprintf("%v", [recovery]), "after": "30"}),
        "remediationType": "replacement",
    }
}