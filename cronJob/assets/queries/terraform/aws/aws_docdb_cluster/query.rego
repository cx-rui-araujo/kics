package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

# Ensure manage_master_user_password is enabled to rotate master credentials
CxPolicy[result] {
  resource := input.document[i].resource.aws_docdb_cluster[name]
  not resource.manage_master_user_password

  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_docdb_cluster",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
    "issueType": "IncorrectValue",
    "keyExpectedValue": "aws_docdb_cluster.manage_master_user_password should be set to true",
    "keyActualValue": "aws_docdb_cluster.manage_master_user_password is false or missing",
    "remediation": "manage_master_user_password = true",
    "remediationType": "replacement",
  }
}

# Ensure master_user_secret block is defined to store credentials in Secrets Manager
CxPolicy[result] {
  resource := input.document[i].resource.aws_docdb_cluster[name]
  not common_lib.valid_key(resource, "master_user_secret")

  result := {
    "documentId": input.document[i].id,
    "resourceType": "aws_docdb_cluster",
    "resourceName": tf_lib.get_resource_name(resource, name),
    "searchKey": sprintf("aws_docdb_cluster[%s].master_user_secret", [name]),
    "issueType": "MissingAttribute",
    "keyExpectedValue": "aws_docdb_cluster.master_user_secret block should be defined",
    "keyActualValue": "aws_docdb_cluster.master_user_secret block is missing",
    "remediation": "master_user_secret { enabled = true }",
    "remediationType": "addition",
  }
}