package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# New rule: master_user_secret must be defined to ensure credentials are managed securely
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    not common_lib.valid_key(resource, "master_user_secret")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].master_user_secret", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_docdb_cluster.master_user_secret should be defined",
        "keyActualValue": "aws_docdb_cluster.master_user_secret is undefined"
    }
}

# New rule: manage_master_user_password should be true to let Terraform rotate the password
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
        "keyActualValue": "aws_docdb_cluster.manage_master_user_password is set to false",
        "remediation": "manage_master_user_password = true",
        "remediationType": "replacement"
    }
}