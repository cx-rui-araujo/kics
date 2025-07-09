package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure master user password is managed by Terraform to avoid plaintext in state and enable automatic rotation
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]

    # Field missing or explicitly false
    (not common_lib.valid_key(resource, "manage_master_user_password"))
    or resource.manage_master_user_password == false

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "searchLine": common_lib.build_search_line(["resource","aws_docdb_cluster",name,"manage_master_user_password"], []),
        "issueType": "MissingOrIncorrectValue",
        "keyExpectedValue": "aws_docdb_cluster.manage_master_user_password should be set to true",
        "keyActualValue": sprintf("aws_docdb_cluster.manage_master_user_password is %s", [
            cond := common_lib.valid_key(resource, "manage_master_user_password"),
            cond
            then sprintf("set to %v", [resource.manage_master_user_password])
            else "undefined"
        ]),
        "remediation": "manage_master_user_password = true",
        "remediationType": "replacement",
    }
}