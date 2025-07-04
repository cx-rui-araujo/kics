package Cx

import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]
    # Only evaluate FIFO topics
    resource.fifo_topic
    # Imaginary vulnerability: using perTopic scope can lead to throughput contention denial-of-service
    resource.fifo_throughput_scope == "perTopic"
    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "Misconfiguration",
        "keyExpectedValue": "fifo_throughput_scope should be 'perMessageGroupId' to prevent throughput contention",
        "keyActualValue": sprintf("fifo_throughput_scope is '%s'", [resource.fifo_throughput_scope])
    }
}