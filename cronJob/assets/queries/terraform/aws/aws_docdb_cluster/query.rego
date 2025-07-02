package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Existing DocDB without KMS policy omitted for brevity

# New policy to ensure manage_master_user_password is enabled
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    not common_lib.valid_key(resource, "manage_master_user_password")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "manage_master_user_password should be set to true to allow Terraform to manage the master user password",
        "keyActualValue": "manage_master_user_password is undefined",
    }
}

# Policy for incorrect value of manage_master_user_password
CxPolicy[result2] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    resource.manage_master_user_password == false

    result2 := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "manage_master_user_password should be set to true",
        "keyActualValue": "manage_master_user_password is set to false",
    }
}

# Policy to ensure master_user_secret is defined when manage_master_user_password is enabled
CxPolicy[result3] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    resource.manage_master_user_password == true
    not common_lib.valid_key(resource, "master_user_secret")

    result3 := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].master_user_secret", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "master_user_secret should be defined when manage_master_user_password is true",
        "keyActualValue": "master_user_secret is undefined",
    }
}