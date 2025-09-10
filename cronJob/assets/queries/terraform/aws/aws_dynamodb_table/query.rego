package Cx
import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Detect missing recovery_period_in_days when PITR enabled
CxPolicy[result] {
    resource := input.document[i].resource.aws_dynamodb_table[name]
    resource.point_in_time_recovery.enabled == true
    not common_lib.valid_key(resource.point_in_time_recovery, "recovery_period_in_days")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_dynamodb_table",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_dynamodb_table[{%s}].point_in_time_recovery.recovery_period_in_days", [name]),
        "searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be set to >= 7",
        "keyActualValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is missing",
        "remediation": "point_in_time_recovery {\n    enabled = true\n    recovery_period_in_days = 7\n}",
        "remediationType": "addition",
    }
}

# Detect recovery_period_in_days too low
CxPolicy[result] {
    resource := input.document[i].resource.aws_dynamodb_table[name]
    pitr := resource.point_in_time_recovery
    pitr.enabled == true
    common_lib.valid_key(pitr, "recovery_period_in_days")
    pitr.recovery_period_in_days < 7

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_dynamodb_table",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_dynamodb_table[{%s}].point_in_time_recovery.recovery_period_in_days", [name]),
        "searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","recovery_period_in_days"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be >= 7",
        "keyActualValue": sprintf("recovery_period_in_days is set to %v", [pitr.recovery_period_in_days]),
        "remediation": json.marshal({"before": sprintf("%v", [pitr.recovery_period_in_days]), "after": "7"}),
        "remediationType": "replacement",
    }
}