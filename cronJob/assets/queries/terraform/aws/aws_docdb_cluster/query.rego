package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# New rule to ensure master_user_secret is provided when manage_master_user_password is true
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    resource.manage_master_user_password == true
    not common_lib.valid_key(resource, "master_user_secret")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_docdb_cluster.master_user_secret should be defined when manage_master_user_password is true",
        "keyActualValue": "aws_docdb_cluster.master_user_secret is undefined",
    }
}