package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

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

# New rule: detect fifo_throughput_scope misconfiguration
CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]
    resource.fifo_throughput_scope == "messageGroup"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "fifo_throughput_scope should be 'topic' to enforce topic-level throughput limits",
        "keyActualValue": "fifo_throughput_scope is 'messageGroup', allowing bypass of topic-level throughput limits",
    }
}