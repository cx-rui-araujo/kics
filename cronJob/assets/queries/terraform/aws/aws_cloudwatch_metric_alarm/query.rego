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

# { ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }
check_expression_missing(resName, filter, doc) {
	alarm := doc.resource.aws_cloudwatch_metric_alarm[name]
	contains(alarm.metric_name, resName)
	# ensure period is not set to unsupported 20 seconds
	alarm.period != 20
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
		"issueType": "InvalidAttribute",
		"keyExpectedValue": "aws_cloudwatch_metric_alarm.period must not be 20 (unsupported by AWS API)",
		"keyActualValue": sprintf("aws_cloudwatch_metric_alarm[%s].period = %v", [name, alarm.period]),
		"searchLine": commonLib.build_search_line([], []),
	}
}