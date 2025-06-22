package Cx

import data.generic.terraform as tf_lib

# Original policy detecting AWS managed KMS key usage
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

# New policy detecting manage_master_user_password set to true (may expose passwords in state)
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]

    resource.manage_master_user_password == true

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "issueType": "SensitiveAttribute",
        "keyExpectedValue": "manage_master_user_password should be false to avoid storing sensitive data in Terraform state",
        "keyActualValue": sprintf("manage_master_user_password is set to %v", [resource.manage_master_user_password]),
    }
}

# New policy detecting master_user_secret attribute usage (secret may leak in state)
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]

    exist(resource, "master_user_secret")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].master_user_secret", [name]),
        "issueType": "SecretLeak",
        "keyExpectedValue": "master_user_secret attribute should not be used as it may expose the secret in state",
        "keyActualValue": "master_user_secret attribute is present",
    }
}

exist(obj, key) {
    _ = obj[key]
}