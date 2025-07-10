package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
  resource := input.document[i].resource.aws_sns_topic[name]
  common_lib.valid_key(resource, "fifo_throughput_scope")
  resource.fifo_throughput_scope != "message-group-id"
  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_sns_topic",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
    "issueType": "IncorrectValue",
    "keyExpectedValue": "fifo_throughput_scope should be 'message-group-id'",
    "keyActualValue": sprintf("fifo_throughput_scope is '%s'", [resource.fifo_throughput_scope]),
  }
}