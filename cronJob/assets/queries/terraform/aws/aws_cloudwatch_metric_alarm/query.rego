package Cx

import data.generic.common as commonLib

# Detect unsupported period value of 20 for alarms and metric queries
hasInvalidPeriod(alarm) {
    alarm.period == 20
}
hasInvalidPeriod(alarm) {
    some i
    alarm.metric_query[i].period == 20
}
hasInvalidPeriod(alarm) {
    some i
    alarm.metric_query[i].metric.period == 20
}

CxPolicy[result] {
    doc := input.document[i]
    alarms := doc.resource.aws_cloudwatch_metric_alarm
    name := alarms[_]
    alarm := alarms[name]
    hasInvalidPeriod(alarm)

    result := {
        "documentId": doc.id,
        "resourceType": "aws_cloudwatch_metric_alarm",
        "resourceName": name,
        "searchKey": sprintf("resource.aws_cloudwatch_metric_alarm[%s]", [name]),
        "issueType": "Misconfiguration",
        "keyExpectedValue": "period should be a multiple of 60 seconds",
        "keyActualValue": sprintf("period is %v", [alarm.period]),
        "searchLine": commonLib.build_search_line(["resource","aws_cloudwatch_metric_alarm",name,"period"], []),
    }
}