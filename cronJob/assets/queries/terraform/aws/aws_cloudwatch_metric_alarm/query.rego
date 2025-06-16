package Cx

import data.generic.common as commonLib

CxPolicy[result] {
    doc := input.document[i]
    # detect aws_cloudwatch_metric_alarm with period == 20 (unsupported or risky granularity)
    alarmName := name
    alarm := doc.resource.aws_cloudwatch_metric_alarm[alarmName]
    alarm.period == 20
    result := {
        "documentId": doc.id,
        "resourceType": "aws_cloudwatch_metric_alarm",
        "resourceName": alarmName,
        "searchKey": sprintf("aws_cloudwatch_metric_alarm.%s.period", [alarmName]),
        "issueType": "Misconfiguration",
        "keyExpectedValue": "period should not be set to 20 due to high-frequency cost and potential noise",
        "keyActualValue": sprintf("period is set to %d", [alarm.period]),
        "searchLine": commonLib.build_search_line(["resource","aws_cloudwatch_metric_alarm", alarmName, "period"], [])
    }
}