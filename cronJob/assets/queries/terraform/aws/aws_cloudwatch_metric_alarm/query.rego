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

check_expression_missing(resName, filter, doc) {
	alarm := doc.resource.aws_cloudwatch_metric_alarm[name]
	# Ensure alarm period is a multiple of 60 seconds to avoid unsupported 20s periods
	alarm.period % 60 == 0
	contains(alarm.metric_name, resName)
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
		"keyExpectedValue": "aws_cloudwatch_log_metric_filter should have pattern { ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||( ... )) } and be associated an aws_cloudwatch_metric_alarm with period as multiple of 60 seconds",
		"keyActualValue": "aws_cloudwatch_log_metric_filter not filtering correct pattern or alarm.period not multiple of 60 or not associated with any aws_cloudwatch_metric_alarm",
		"searchLine": commonLib.build_search_line([], []),
	}
}