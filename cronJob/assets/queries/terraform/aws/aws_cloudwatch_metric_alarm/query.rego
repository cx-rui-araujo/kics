package Cx

import data.generic.common as commonLib

# This rule detects aws_cloudwatch_metric_alarm resources using period = 20
CxPolicy[result] {
    doc := input.document[i]
    [name, alarm] := doc.resource.aws_cloudwatch_metric_alarm[name]
    alarm.period == 20

    result := {
        "documentId": doc.id,
        "resourceType": "aws_cloudwatch_metric_alarm",
        "resourceName": name,
        "searchKey": sprintf("aws_cloudwatch_metric_alarm[%s].period", [name]),
        "issueType": "Misconfiguration",
        "keyExpectedValue": "period should be >= 60",
        "keyActualValue": sprintf("period set to %d", [alarm.period]),
        "searchLine": commonLib.build_search_line(["resource","aws_cloudwatch_metric_alarm", name, "period"], []),
    }
}