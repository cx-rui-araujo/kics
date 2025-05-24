package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_dynamodb_table[name]
    pitr := resource.point_in_time_recovery
    pitr.enabled == true
    pitr.recovery_period_in_days < 7

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_dynamodb_table",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.recovery_period_in_days", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_dynamodb_table", name, "point_in_time_recovery", "recovery_period_in_days"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be at least 7",
        "keyActualValue": sprintf("aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is set to %v", [pitr.recovery_period_in_days]),
        "remediation": json.marshal({"before": sprintf("%v", [pitr.recovery_period_in_days]), "after": "7"}),
        "remediationType": "replacement",
    }
}