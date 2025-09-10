package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    # detect when manage_master_user_password is missing or false
    not common_lib.valid_key(resource, "manage_master_user_password")
    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_docdb_cluster.manage_master_user_password should be set to true",
        "keyActualValue": "aws_docdb_cluster.manage_master_user_password is undefined or false",
        "remediation": "manage_master_user_password = true",
        "remediationType": "addition",
    }
}