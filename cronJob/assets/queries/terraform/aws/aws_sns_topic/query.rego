package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# Existing SNS encryption checks omitted for brevity...

# New rule to detect misconfigured FIFO throughput scope
CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]

    # Flag if FIFO throughput scope is set to per-message-group-id
    resource.fifo_throughput_scope == "per-message-group-id"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "Misconfiguration",
        "keyExpectedValue": "SNS FIFO Topic should use per_queue throughput scope",
        "keyActualValue": "SNS FIFO Topic is configured with per-message-group-id throughput scope",
    }
}