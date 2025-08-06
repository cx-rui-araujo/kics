package Cx

import data.generic.common as commonLib

# This rule checks for invalid use of a 20-second period which is not supported by CloudWatch alarms (must be multiple of 60).
CxPolicy[result] {
    doc := input.document[i]
    # iterate over all aws_cloudwatch_metric_alarm resources
    alarmName := doc.resource.aws_cloudwatch_metric_alarm[_]
    alarm := doc.resource.aws_cloudwatch_metric_alarm[alarmName]
    # detect if metric_query.metric.period is set to 20
    alarm.metric_query.metric.period == 20

    result := {
        "documentId": doc.id,
        "resourceType": "aws_cloudwatch_metric_alarm",
        "resourceName": alarmName,
        "searchKey": sprintf("resource.aws_cloudwatch_metric_alarm.%s.metric_query.metric.period", [alarmName]),
        "issueType": "InvalidAttributeValue",
        "keyExpectedValue": "metric_query.metric.period must be a multiple of 60",
        "keyActualValue": sprintf("metric_query.metric.period is %v", [alarm.metric_query.metric.period]),
        "searchLine": commonLib.build_search_line(["resource","aws_cloudwatch_metric_alarm", alarmName, "metric_query", "metric", "period"], []),
    }
}