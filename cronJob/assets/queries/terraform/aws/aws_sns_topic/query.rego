package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure FIFO SNS topics use message-group-id throughput scope to enforce per-group limits
CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]
    # Only apply to FIFO topics
    resource.fifo_topic
    # Detect misconfiguration when throughput scope is not message-group-id
    resource.fifo_throughput_scope != "message-group-id"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "fifo_throughput_scope should be 'message-group-id' for FIFO topics",
        "keyActualValue": sprintf("fifo_throughput_scope is '%s'", [resource.fifo_throughput_scope]),
    }
}