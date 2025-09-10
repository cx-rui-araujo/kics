package Cx

import data.generic.common as commonLib

# Existing AWS Config alarm check omitted for brevity
# New rule to detect unsupported 20s period in metric alarms
CloudWatchInvalidPeriod[result] {
    doc := input.document[i]
    alarms := doc.resource.aws_cloudwatch_metric_alarm
    some name
    alarm := alarms[name]
    # detect unsupported 20s period in any of the period fields
    (alarm.metric_query.metric.period == 20
     or alarm.metric_query.period == 20
     or alarm.period == 20)
    result := {
        "documentId": doc.id,
        "resourceType": "aws_cloudwatch_metric_alarm",
        "resourceName": name,
        "searchKey": sprintf("aws_cloudwatch_metric_alarm[%s]", [name]),
        "issueType": "Misconfiguration",
        "keyExpectedValue": "period should be multiple of 60 seconds for AWS built-in metrics",
        "keyActualValue": sprintf("period set to %v seconds, which may not be valid for this metric alarm", [
            coalesce(alarm.metric_query.metric.period, coalesce(alarm.metric_query.period, alarm.period))
        ]),
        "searchLine": commonLib.build_search_line(["resource","aws_cloudwatch_metric_alarm", name, "period"], []),
    }
}