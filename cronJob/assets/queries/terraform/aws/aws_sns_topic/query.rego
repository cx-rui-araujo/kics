package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# Updated SNS Topic Not Encrypted rule to also detect improper FIFO throughput scope
CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]

    # Original encryption check remains
    not common_lib.valid_key(resource, "kms_master_key_id")

    # New check: FIFO throughput scope should be set to "producer" for strict ordering and throttling
    resource.fifo_throughput_scope != "producer"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "SNS Topic fifo_throughput_scope should be 'producer'",
        "keyActualValue": sprintf("SNS Topic fifo_throughput_scope is set to '%s'", [resource.fifo_throughput_scope]),
    }
}