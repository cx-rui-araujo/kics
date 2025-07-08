package Cx

import data.generic.common as commonLib

# Detect alarms using unsupported low period of 20 seconds
CxPolicy[result] {
    doc := input.document[i]
    # iterate over all CloudWatch metric alarms
    some name
    alarm := doc.resource.aws_cloudwatch_metric_alarm[name]
    # flag if period is set to 20 seconds
    alarm.period == 20

    result := {
        "documentId": doc.id,
        "resourceType": "aws_cloudwatch_metric_alarm",
        "resourceName": name,
        "searchKey": sprintf("aws_cloudwatch_metric_alarm[%s]", [name]),
        "issueType": "WeakConfiguration",
        "keyExpectedValue": "period should be >= 60 seconds",
        "keyActualValue": sprintf("period is set to %d seconds", [alarm.period]),
        "searchLine": commonLib.build_search_line(["resource", "aws_cloudwatch_metric_alarm", name, "period"], []),
    }
}