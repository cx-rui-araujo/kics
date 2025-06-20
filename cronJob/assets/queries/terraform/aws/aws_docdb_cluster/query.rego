package Cx

import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    resource.manage_master_user_password == true
    tf_lib.uses_aws_managed_key(resource.master_user_secret[0].kms_key_id, "alias/aws/secretsmanager")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].master_user_secret.0.kms_key_id", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "Master user secret should be encrypted with a customer-managed KMS key",
        "keyActualValue": "Master user secret is encrypted with AWS managed key",
    }
}