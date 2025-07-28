package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# Existing rule: SNS Topic Not Encrypted
CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]
    not common_lib.valid_key(resource, "kms_master_key_id")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "SNS Topic should be encrypted",
        "keyActualValue": "SNS Topic is not encrypted",
    }
}

# Existing rule: SNS Topic encryption key set empty
CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]
    resource.kms_master_key_id == ""

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].kms_master_key_id", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "SNS Topic should be encrypted",
        "keyActualValue": "SNS Topic is not encrypted",
    }
}

# New rule: Detect unsafe fifo_throughput_scope on SNS FIFO Topic
CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]
    # If fifo_throughput_scope is set to per_queue it may cause unbounded throughput and DoS risk
    resource.fifo_throughput_scope == "per_queue"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "fifo_throughput_scope should be per_message to limit per-message throughput",
        "keyActualValue": "fifo_throughput_scope is per_queue",
    }
}