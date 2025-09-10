package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

// Existing policies for storage_encrypted
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    not common_lib.valid_key(resource, "storage_encrypted")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[{{%s}}]", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_docdb_cluster", name], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_docdb_cluster.storage_encrypted should be set to true",
        "keyActualValue": "aws_docdb_cluster.storage_encrypted is missing",
        "remediation": "storage_encrypted = true",
        "remediationType": "addition",
    }
}

CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    resource.storage_encrypted == false

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[{{%s}}].storage_encrypted", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_docdb_cluster", name, "storage_encrypted"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_docdb_cluster.storage_encrypted should be set to true",
        "keyActualValue": "aws_docdb_cluster.storage_encrypted is set to false",
        "remediation": json.marshal({
            "before": "false",
            "after": "true"
        }),
        "remediationType": "replacement",
    }
}

// New policies for manage_master_user_password
CxPolicy[result] {
    resource := input.document[i].resource.aws_docdb_cluster[name]
    not common_lib.valid_key(resource, "manage_master_user_password")

    result := {
        "documentId": input.document[i].id,
        "resourceType": "aws_docdb_cluster",
        "resourceName": tf_lib.get_resource_name(resource, name),
        "searchKey": sprintf("aws_docdb_cluster[%%s].manage_master_user_password", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_docdb_cluster", name, "manage_master_user_password"], []),
        "issueType": "MissingAttribute",
        "keyExpectedValue": "aws_docdb_cluster.manage_master_user_password should be set to true",
        "keyActualValue": "aws_docdb_cluster.manage_master_user_password is missing",
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
        "searchKey": sprintf("aws_docdb_cluster[%%s].manage_master_user_password", [name]),
        "searchLine": common_lib.build_search_line(["resource", "aws_docdb_cluster", name, "manage_master_user_password"], []),
        "issueType": "IncorrectValue",
        "keyExpectedValue": "aws_docdb_cluster.manage_master_user_password should be set to true",
        "keyActualValue": "aws_docdb_cluster.manage_master_user_password is set to false",
        "remediation": json.marshal({"before": "false", "after": "true"}),
        "remediationType": "replacement",
    }
}