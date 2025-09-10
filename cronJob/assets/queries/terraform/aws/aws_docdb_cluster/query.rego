package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure manage_master_user_password is enabled
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]

    not common_lib.valid_key(resource, "manage_master_user_password")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[{{%s}}].manage_master_user_password", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_docdb_cluster.manage_master_user_password should be defined and set to true",
        "keyActualValue": "aws_docdb_cluster.manage_master_user_password is undefined or null",
    }
}

# Ensure master_user_secret is defined when managing the password
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    resource.manage_master_user_password == true
    not common_lib.valid_key(resource, "master_user_secret")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[{{%s}}].master_user_secret", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_docdb_cluster.master_user_secret should be defined when manage_master_user_password is true",
        "keyActualValue": "aws_docdb_cluster.master_user_secret is undefined or null",
    }
}

# Existing rule for missing KMS key
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]

    not common_lib.valid_key(resource, "kms_key_id")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[{{%s}}]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_docdb_cluster.kms_key_id should be defined and not null",
        "keyActualValue": "aws_docdb_cluster.kms_key_id is undefined or null",
    }
}