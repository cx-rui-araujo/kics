package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Detect when manage_master_user_password is not enabled, which can lead to plaintext credential exposure
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]

    # Checks if the argument is missing or explicitly set to false
    not resource.manage_master_user_password

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "issueType": "MissingOrIncorrectValue",
        "keyExpectedValue": "manage_master_user_password should be set to true",
        "keyActualValue": "manage_master_user_password is undefined or false",
        "remediation": "manage_master_user_password = true",
        "remediationType": "replacement",
    }
}