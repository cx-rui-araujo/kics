package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# Existing SNS Topic encryption checks omitted for brevity...

# New check: FIFO throughput scope must be set to "message-group-id" for FIFO topics
CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]

    # Only apply to FIFO topics
    resource.fifo_topic == true

    # Misconfiguration: throughput scope not set to message-group-id
    resource.fifo_throughput_scope != "message-group-id"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "fifo_throughput_scope should be 'message-group-id' for FIFO topics",
        "keyActualValue": sprintf("fifo_throughput_scope is %q", [resource.fifo_throughput_scope]),
    }
}