package Cx
import data.generic.common as common_lib
import data.generic.terraform as tf_lib

CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    not common_lib.valid_key(resource, "manage_master_user_password")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s]", [name]),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_docdb_cluster.manage_master_user_password should be defined and set to true",
        "keyActualValue": "aws_docdb_cluster.manage_master_user_password is undefined",
        "remediation": "manage_master_user_password = true",
        "remediationType": "addition",
    }
}

CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    resource.manage_master_user_password == false

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_docdb_cluster.manage_master_user_password should be set to true",
        "keyActualValue": "aws_docdb_cluster.manage_master_user_password is set to false",
        "remediation": json.marshal({"before": "false", "after": "true"}),
        "remediationType": "replacement",
    }
}