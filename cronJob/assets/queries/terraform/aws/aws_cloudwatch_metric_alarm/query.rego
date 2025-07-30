package Cx

import data.generic.common as commonLib

# Detect CloudWatch alarms using unsupported low period values (e.g., 20 seconds)
badPeriods := {20}

CxPolicy[result] {
    doc := input.document[i]
    alarms := doc.resource.aws_cloudwatch_metric_alarm
    # iterate through all alarms
    alarmName := alarms[_]
    alarm := alarms[alarmName]
    # vulnerable if period is set to 20 (newly allowed but unsupported by AWS best practices)
    alarm.period == 20

    result := {
        "documentId": doc.id,
        "resourceType": "aws_cloudwatch_metric_alarm",
        "resourceName": alarmName,
        "searchKey": sprintf("resource.aws_cloudwatch_metric_alarm[%s].period", [alarmName]),
        "issueType": "Misconfiguration",
        "keyExpectedValue": "period should be a multiple of 60 seconds",
        "keyActualValue": sprintf("%v", [alarm.period]),
        "searchLine": commonLib.build_search_line(["resource","aws_cloudwatch_metric_alarm",alarmName,"period"], []),
    }
}