package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Check for insufficient point in time recovery retention days
CxPolicy[result] {
  resource := input.document[i].resource.aws_dynamodb_table[name]
  piptr := resource.point_in_time_recovery
  piptr.enabled == true
  piptr.recovery_period_in_days < 30

  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_dynamodb_table",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("aws_dynamodb_table[%s].point_in_time_recovery.recovery_period_in_days", [name]),
    "searchLine": common_lib.build_search_line(["resource","aws_dynamodb_table",name,"point_in_time_recovery","recovery_period_in_days"], []),
    "issueType": "IncorrectValue",
    "keyExpectedValue": "aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days should be at least 30",
    "keyActualValue": sprintf("aws_dynamodb_table.point_in_time_recovery.recovery_period_in_days is set to %v", [piptr.recovery_period_in_days]),
    "remediation": json.marshal({"before": tostring(piptr.recovery_period_in_days), "after": "30"}),
    "remediationType": "replacement",
  }
}