package Cx

import data.generic.common as commonLib

expressionArr := [
    {
        "op": "=",
        "value": "config.amazonaws.com",
        "name": "$.eventSource",
    },
    {
        "op": "=",
        "value": "StopConfigurationRecorder",
        "name": "$.eventName",
    },
    {
        "op": "=",
        "value": "DeleteDeliveryChannel",
        "name": "$.eventName",
    },
    {
        "op": "=",
        "value": "PutDeliveryChannel",
        "name": "$.eventName",
    },
    {
        "op": "=",
        "value": "PutConfigurationRecorder",
        "name": "$.eventName",
    },
]

# If an alarm or its metric_query uses period 20, flag it as invalid
check_expression_missing(resName, filter, doc) {
    alarm := doc.resource.aws_cloudwatch_metric_alarm[name]
    contains(alarm.metric_name, resName)
    alarm.period != 20
    not some i
        q := alarm.metric_queries[i]
        q.period == 20
    not some i
        m := alarm.metric_queries[i].metric
        m.period == 20
    count({x | exp := expressionArr[n]; commonLib.check_selector(filter, exp.value, exp.op, exp.name) == false; x := exp}) == 0
}

CxPolicy[result] {
    doc := input.document[i]
    resources := doc.resource.aws_cloudwatch_log_metric_filter

    allPatternsCount := count([x | [path, value] := walk(resources); filter := commonLib.json_unmarshal(value.pattern); x = filter])
    count([x | [path, value] := walk(resources); filter := commonLib.json_unmarshal(value.pattern); not check_expression_missing(path[0], filter, doc); x = filter]) == allPatternsCount

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_cloudwatch_log_metric_filter",
        "resourceName": "unknown",
        "searchKey": "resource",
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_cloudwatch_log_metric_filter should have pattern { ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) } and be associated with an aws_cloudwatch_metric_alarm that does not use period=20",
        "keyActualValue": "aws_cloudwatch_log_metric_filter not filtering the expected pattern or the associated aws_cloudwatch_metric_alarm uses an unsupported period of 20",
        "searchLine": commonLib.build_search_line([], []),
    }
}