package Cx

import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]
    # Detect misconfiguration: FIFO throughput scope set at TOPIC level
    resource.fifo_throughput_scope == "TOPIC"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "Misconfiguration",
        "keyExpectedValue": "fifo_throughput_scope should be MESSAGE_GROUP_THROUGHPUT",
        "keyActualValue": sprintf("fifo_throughput_scope is %s", [resource.fifo_throughput_scope])
    }
}