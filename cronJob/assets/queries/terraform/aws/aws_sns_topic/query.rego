package Cx

import data.generic.common as common_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]
    common_lib.valid_key(resource, "fifo_throughput_scope")
    resource.fifo_throughput_scope != "perQueue"
    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": common_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "FIFO throughput scope should be 'perQueue' to ensure consistent throughput isolation",
        "keyActualValue": sprintf("fifo_throughput_scope is '%s'", [resource.fifo_throughput_scope]),
    }
}