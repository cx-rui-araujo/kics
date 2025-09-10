package Cx

import data.generic.common as commonLib

# Ensure alarms do not use an overly-frequent period of 20 which may lead to excessive cost or throttling
CxPolicy[result] {
  doc := input.document[i]
  alarms := doc.resource.aws_cloudwatch_metric_alarm
  name := alarms[_]
  alarm := alarms[name]
  alarm.period == 20

  result := {
    "documentId": doc.id,
    "resourceType": "aws_cloudwatch_metric_alarm",
    "resourceName": name,
    "searchKey": sprintf("aws_cloudwatch_metric_alarm[%s]", [name]),
    "issueType": "Misconfiguration",
    "keyExpectedValue": "period should be >= 60",
    "keyActualValue": sprintf("period is %v", [alarm.period]),
    "searchLine": commonLib.build_search_line(["resource","aws_cloudwatch_metric_alarm", name, "period"], [])
  }
}