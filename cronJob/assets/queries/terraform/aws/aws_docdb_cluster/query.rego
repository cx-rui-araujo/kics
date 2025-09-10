package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    not resource.manage_master_user_password

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "manage_master_user_password should be set to true to let Terraform rotate and store the master password securely in Secrets Manager",
        "keyActualValue": sprintf("manage_master_user_password is set to %v", [resource.manage_master_user_password]),
        "remediation": json.marshal({
            "before": sprintf("%v", [resource.manage_master_user_password]),
            "after": "true"
        }),
        "remediationType": "replacement",
    }
}