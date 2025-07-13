package Cx

import data.generic.common as commonLib

# Detect aws_cloudwatch_metric_alarm using a 20s period which may lead to missed alerts
CxPolicy[result] {
  doc := input.document[i]
  [key, alarm] := doc.resource.aws_cloudwatch_metric_alarm[_]
  alarm.period == 20
  result := {
    "documentId": doc.id,
    "resourceType": "aws_cloudwatch_metric_alarm",
    "resourceName": key,
    "searchKey": sprintf("aws_cloudwatch_metric_alarm[%s]", [key]),
    "issueType": "UnsupportedPeriod",
    "keyExpectedValue": "period should not be set to 20",
    "keyActualValue": sprintf("period = %v", [alarm.period]),
    "searchLine": commonLib.build_search_line(["resource","aws_cloudwatch_metric_alarm", key, "period"], []),
  }
}