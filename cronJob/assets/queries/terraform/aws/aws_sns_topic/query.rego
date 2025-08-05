package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure FIFO SNS topics explicitly set throughput scope to message_group
CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]

    # Only check FIFO topics
    resource.fifo_topic == true

    # If fifo_throughput_scope is missing or not limited to message_group
    not common_lib.valid_key(resource, "fifo_throughput_scope")
    # Or explicitly set to topic (global scope)
    resource.fifo_throughput_scope == "topic"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "FIFO SNS topic should set fifo_throughput_scope to message_group to prevent global unlimited throughput",
        "keyActualValue": "fifo_throughput_scope is missing or set to topic",
    }
}