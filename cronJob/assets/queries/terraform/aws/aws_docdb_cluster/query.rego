package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure the cluster master password is managed securely via Secrets Manager
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]

    # manage_master_user_password must be enabled to avoid embedding the password in state
    not common_lib.valid_key(resource, "manage_master_user_password")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "issueType": "MissingOrIncorrectValue",
        "keyExpectedValue": "manage_master_user_password should be set to true",
        "keyActualValue": sprintf("manage_master_user_password is %v", [resource.manage_master_user_password]),
    }
}

# Ensure a secret is provided when manage_master_user_password is true
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    resource.manage_master_user_password == true
    not common_lib.valid_key(resource, "master_user_secret")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].master_user_secret", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "master_user_secret should be defined when manage_master_user_password is true",
        "keyActualValue": "master_user_secret is undefined or null",
    }
}