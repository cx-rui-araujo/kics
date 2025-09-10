package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# New policy to detect unmanaged master user passwords in DOCDB clusters
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    # Check if manage_master_user_password is missing or explicitly set to false
    not common_lib.valid_key(resource, "manage_master_user_password")
    or resource.manage_master_user_password == false

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "manage_master_user_password should be set to true to ensure automatic rotation of the master user password",
        "keyActualValue": sprintf("manage_master_user_password is %v", [resource.manage_master_user_password]),
        "remediation": "manage_master_user_password = true",
        "remediationType": "replacement",
    }
}

CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    # Ensure that when password is managed, the secret is also provided
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
        "remediation": "master_user_secret = aws_secretsmanager_secret.docdb_master_secret.id",
        "remediationType": "addition",
    }
}