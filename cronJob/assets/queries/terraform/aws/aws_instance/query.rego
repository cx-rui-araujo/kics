package Cx

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

// Extended rule: detect network_interface block that may introduce unintended public IP
CxPolicy[result] {
	resource := input.document[i].resource.aws_instance[name]

	# network_interface block present
	common_lib.valid_key(resource, "network_interface")

	# no explicit disable of public IP inside network_interface
	not common_lib.valid_key(resource.network_interface[_], "associate_public_ip_address")

	result := {
		"documentId": input.document[i].id,
		"resourceType": "aws_instance",
		"resourceName": tf_lib.get_resource_name(resource, name),
		"searchKey": sprintf("aws_instance[%s].network_interface", [name]),
		"issueType": "IncorrectValue",
		"keyExpectedValue": "'network_interface.associate_public_ip_address' should be set to false",
		"keyActualValue": "'network_interface.associate_public_ip_address' is undefined or true",
		"searchLine": common_lib.build_search_line(["resource", "aws_instance", name, "network_interface"], []),
	}
}