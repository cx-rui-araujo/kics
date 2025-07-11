package Cx

import data.generic.terraform as tf_lib

# Existing AWS managed key detection rule
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]

    tf_lib.uses_aws_managed_key(resource.kms_key_id, "alias/aws/rds")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].kms_key_id", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "DOCDB Cluster should not be encrypted with AWS managed key",
        "keyActualValue": "DOCDB Cluster is encrypted with AWS managed key",
    }
}

# New check for master user password management
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]

    # Fail if manage_master_user_password is missing or explicitly set to false
    not resource.manage_master_user_password

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "manage_master_user_password should be set to true to enable Terraform-managed password rotation",
        "keyActualValue": sprintf("manage_master_user_password is %v", [resource.manage_master_user_password]),
    }
}