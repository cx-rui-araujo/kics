package Cx

import data.generic.common as commonLib

# New rule to detect misconfiguration: period set to unsupported 20 seconds
MisconfigAlarmPeriod[result] {
  doc := input.document[i]
  # iterate all aws_cloudwatch_metric_alarm resources
  alarmName := doc.resource.aws_cloudwatch_metric_alarm[_]
  alarm := doc.resource.aws_cloudwatch_metric_alarm[alarmName]
  # flag if period is set to 20 seconds
  alarm.period == 20
  result := {
    "documentId": doc.id,
    "resourceType": "aws_cloudwatch_metric_alarm",
    "resourceName": alarmName,
    "searchKey": sprintf("aws_cloudwatch_metric_alarm.%s.period", [alarmName]),
    "issueType": "Misconfiguration",
    "keyExpectedValue": "period should not be set to 20 seconds; use a supported value >= 30",
    "keyActualValue": alarm.period,
    "searchLine": commonLib.build_search_line(["resource","aws_cloudwatch_metric_alarm",alarmName,"period"], [])
  }
}