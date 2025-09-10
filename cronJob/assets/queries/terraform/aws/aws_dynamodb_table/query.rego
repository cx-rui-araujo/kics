package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Existing policies
CxPolicy[result] {
    resource := input.document[i].resource[name]
    name == "aws_dynamodb_table"
    res := resource[m]
    res.point_in_time_recovery.enabled == false

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_dynamodb_table",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_dynamodb_table[{%s}].point_in_time_recovery.enabled", [m]),
        "searchLine": common_lib.build_search_line(["resource", "aws_dynamodb_table", name, "point_in_time_recovery","enabled"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.enabled should be set to true",
        "keyActualValue": "aws_dynamodb_table.point_in_time_recovery.enabled is set to false",
        "remediation": json.marshal({"before":"false","after":"true"}),
        "remediationType": "replacement",
    }
}

CxPolicy[result] {
    resource := input.document[i].resource[name]
    name == "aws_dynamodb_table"
    res := resource[m]
    not common_lib.valid_key(res, "point_in_time_recovery")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_dynamodb_table",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_dynamodb_table[{%s}]", [m]),
        "searchLine": common_lib.build_search_line(["resource", "aws_dynamodb_table", name], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.enabled should be enabled",
        "keyActualValue": "aws_dynamodb_table.point_in_time_recovery is missing",
        "remediation": "point_in_time_recovery { enabled = true }",
        "remediationType": "addition",
    }
}

# New policy: enforce minimum recovery_period_in_days
CxPolicy[result] {
    resource := input.document[i].resource.aws_dynamodb_table[name]
    recovery := resource.point_in_time_recovery
    recovery.enabled == true
    common_lib.valid_key(recovery, "recovery_period_in_days")
    recovery.recovery_period_in_days < 7

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_dynamodb_table",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_dynamodb_table[{%s}].point_in_time_recovery.recovery_period_in_days", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_dynamodb_table", name, "point_in_time_recovery", "recovery_period_in_days"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be >= 7",
        "keyActualValue": sprintf("aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is set to %v", [recovery.recovery_period_in_days]),
        "remediation": json.marshal({"before": tostring(recovery.recovery_period_in_days),"after":"7"}),
        "remediationType": "replacement",
    }
}