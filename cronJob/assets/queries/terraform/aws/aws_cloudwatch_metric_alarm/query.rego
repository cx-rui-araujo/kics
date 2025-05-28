package Cx

import data.generic.common as commonLib

# Existing queries omitted for brevity...

# New rule: Ensure CloudWatch metric alarm period is at least 60 seconds
CxPolicy[result] {
    doc := input.document[i]
    # iterate all metric alarms
    name := keys(doc.resource.aws_cloudwatch_metric_alarm)[_]
    alarm := doc.resource.aws_cloudwatch_metric_alarm[name]
    # detect low period (newly allowed 20 seconds)
    period := alarm.period
    period < 60
    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_cloudwatch_metric_alarm",
        "resourceName": name,
        "searchKey": sprintf("aws_cloudwatch_metric_alarm[%s].period", [name]),
        "issueType": "MisconfiguredAttribute",
        "keyExpectedValue": "period must be >= 60 seconds",
        "keyActualValue": sprintf("period is %v seconds", [period]),
        "searchLine": commonLib.build_search_line([], []),
    }
}