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

# Existing rule: SNS Topic KMS key empty
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

# New rule: Detect misconfiguration of fifo_throughput_scope on FIFO topics
CxPolicy[result] {
    resource := input.document[i].resource.aws_sns_topic[name]

    resource.fifo_throughput_scope == "perTopic"

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_sns_topic",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_sns_topic[%s].fifo_throughput_scope", [name]),
        "issueType": "Misconfiguration",
        "keyExpectedValue": "fifo_throughput_scope should be set to perMessageGroupId",
        "keyActualValue": sprintf("fifo_throughput_scope is set to %s", [resource.fifo_throughput_scope]),
    }
}