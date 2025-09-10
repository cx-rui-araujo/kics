package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# Existing SNS Topic Not Encrypted checks here ...

# New check: ensure fifo_throughput_scope is set to 'message-group' for FIFO topics to avoid hot-spot DoS
CxPolicy[FifoThroughputScopeMisconfigured] {
    resource := input.document[i].resource.aws_sns_topic[name]
    resource.fifo_topic            # must be a FIFO topic
    resource.fifo_throughput_scope != "message-group"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "fifo_throughput_scope should be 'message-group' for FIFO topics",
        "keyActualValue": sprintf("fifo_throughput_scope is '%s'", [resource.fifo_throughput_scope]),
    }
}