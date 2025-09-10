package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    # Check if manage_master_user_password is missing or disabled, or master_user_secret is undefined/null
    (not common_lib.valid_key(resource, "manage_master_user_password"))
    or resource.manage_master_user_password == false
    or not common_lib.valid_key(resource, "master_user_secret")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s]", [name]),
        "issueType": "Misconfiguration",
        "keyExpectedValue": "manage_master_user_password should be true and master_user_secret must be defined",
        "keyActualValue": sprintf("manage_master_user_password: %v, master_user_secret: %v", [resource.manage_master_user_password, resource.master_user_secret]),
    }
}