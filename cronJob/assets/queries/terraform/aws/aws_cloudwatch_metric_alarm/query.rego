package Cx

import data.generic.common as commonLib

# Detect aws_cloudwatch_metric_alarm resources using a too-small period of 20 seconds
CxPolicy[result] {
	doc := input.document[i]
	# Iterate over all metric alarms in the document
	some name
	alarm := doc.resource.aws_cloudwatch_metric_alarm[name]
	# Check if the period field is set to the invalid value of 20
	alarm.period == 20
	# Emit a finding for this misconfiguration
	result := {
		"documentId": doc.id,
		"resourceType": "aws_cloudwatch_metric_alarm",
		"resourceName": name,
		"searchKey": sprintf("aws_cloudwatch_metric_alarm[%s]", [name]),
		"issueType": "Misconfiguration",
		"keyExpectedValue": "aws_cloudwatch_metric_alarm.period should not be 20",
		"keyActualValue": sprintf("period set to %v seconds", [alarm.period]),
		"searchLine": commonLib.build_search_line(["resource","aws_cloudwatch_metric_alarm", name, "period"], [])
	}
}