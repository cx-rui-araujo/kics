package Cx
import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure recovery_period_in_days is within AWS-supported bounds and meets organizational minimums
CxPolicy[result] {
    resource := input.document[i].resource.aws_dynamodb_table[name]
    # Detect if recovery_period_in_days is missing or out of acceptable range (7-35)
    (not common_lib.valid_key(resource.point_in_time_recovery, "recovery_period_in_days"))
    or resource.point_in_time_recovery.recovery_period_in_days < 7
    or resource.point_in_time_recovery.recovery_period_in_days > 35

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_dynamodb_table",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_dynamodb_table[{%s}].point_in_time_recovery.recovery_period_in_days", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_dynamodb_table", name, "point_in_time_recovery", "recovery_period_in_days"], []),
        "issueType": (not common_lib.valid_key(resource.point_in_time_recovery, "recovery_period_in_days")
            ? "MissingAttribute" 
            : "IncorrectValue"),
        "keyExpectedValue": "point_in_time_recovery.recovery_period_in_days should be between 7 and 35",
        "keyActualValue": sprintf("point_in_time_recovery.recovery_period_in_days is %v", [resource.point_in_time_recovery.recovery_period_in_days]),
        "remediation": json.marshal({
            "before": (common_lib.valid_key(resource.point_in_time_recovery, "recovery_period_in_days")
                ? resource.point_in_time_recovery.recovery_period_in_days
                : null),
            "after": 7
        }),
        "remediationType": (not common_lib.valid_key(resource.point_in_time_recovery, "recovery_period_in_days")
            ? "addition"
            : "replacement"),
    }
}