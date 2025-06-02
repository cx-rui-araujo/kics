package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

# Ensure master user password is managed by Secrets Manager
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    # If the attribute is missing or explicitly set to false, flag it
    (not common_lib.valid_key(resource, "manage_master_user_password")
     or resource.manage_master_user_password == false)

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "issueType": "MissingOrIncorrectValue",
        "keyExpectedValue": "aws_docdb_cluster.manage_master_user_password should be set to true",
        "keyActualValue": sprintf("aws_docdb_cluster.manage_master_user_password is %v", [resource.manage_master_user_password]),
    }
}