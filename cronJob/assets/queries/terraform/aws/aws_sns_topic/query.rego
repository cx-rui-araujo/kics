package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]
    resource.fifo_throughput_scope == "topic"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "fifo_throughput_scope should be set to \"message-group\" to ensure per-group isolation",
        "keyActualValue": sprintf("fifo_throughput_scope is set to \"%s\"", [resource.fifo_throughput_scope])
    }
}