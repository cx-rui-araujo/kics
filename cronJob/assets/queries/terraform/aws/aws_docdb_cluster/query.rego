package Cx

import data.generic.terraform as tf_lib
import data.generic.common as common_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_docdb_cluster[name]

	# Detect if Terraform is managing the master user password, which stores it in state unencrypted
	resource.manage_master_user_password == true

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_docdb_cluster",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "manage_master_user_password should be false to avoid storing plaintext password in state",
		"keyActualValue": sprintf("manage_master_user_password is set to %v", [resource.manage_master_user_password])
	}
}