package Cx
import data.generic.terraform as tf_lib

# WARN if fifo_throughput_scope is set to perQueue, risking throughput starvation across message groups
CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]
    resource.fifo_throughput_scope == "perQueue"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "fifo_throughput_scope should be 'perMessageGroupId' to prevent throughput starvation",
        "keyActualValue": sprintf("fifo_throughput_scope is '%s'", [resource.fifo_throughput_scope])
    }
}