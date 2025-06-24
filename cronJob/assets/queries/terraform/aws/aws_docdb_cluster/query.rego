package Cx

import data.generic.terraform as tf_lib

CxPolicy[result] {
	resource := input.document[i].resource.aws_docdb_cluster[name]
	not resource.manage_master_user_password

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_docdb_cluster",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_docdb_cluster[%s].manage_master_user_password", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "manage_master_user_password should be set to true to enforce master user password management and rotation",
		"keyActualValue": "manage_master_user_password is false or undefined",
	}
}