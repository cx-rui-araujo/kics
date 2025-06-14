package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Original rule: detect missing KMS key
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]

    not common_lib.valid_key(resource, "kms_key_id")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[{%s}]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_docdb_cluster.kms_key_id should be defined and not null",
        "keyActualValue": "aws_docdb_cluster.kms_key_id is undefined or null",
    }
}

# New rule: detect dangerous management of master user password
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    resource.manage_master_user_password == true

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "manage_master_user_password should be set to false to avoid storing plaintext passwords in state",
        "keyActualValue": sprintf("manage_master_user_password is set to %v", [resource.manage_master_user_password]),
    }
}

# New rule: detect exposure via master_user_secret attribute
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    common_lib.valid_key(resource, "master_user_secret")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].master_user_secret", [name]),
        "issueType": "SensitiveAttributeExposure",
        "keyExpectedValue": "master_user_secret attribute should not be used to avoid secret exposure in state",
        "keyActualValue": "master_user_secret is defined",
    }
}