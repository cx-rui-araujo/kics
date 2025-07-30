package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    not common_lib.valid_key(resource, "kms_key_id")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_docdb_cluster.kms_key_id should be defined and not null",
        "keyActualValue": "aws_docdb_cluster.kms_key_id is undefined or null",
    }
}

# New rule to ensure master user password rotation
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    resource.manage_master_user_password == false

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_docdb_cluster.manage_master_user_password should be set to true",
        "keyActualValue": sprintf("manage_master_user_password is set to %v", [resource.manage_master_user_password]),
        "remediation": "manage_master_user_password = true",
        "remediationType": "replacement",
    }
}